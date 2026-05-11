package starlarkext

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"go.starlark.net/starlark"
)

// SetupAzureAPI registers the az.* namespace into the Starlark environment.
//
// Credentials: standard Azure credential chain via DefaultAzureCredential
// (AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET env vars, workload
// identity, managed identity, Azure CLI credentials — in that order).
//
// Starlark API:
//
//	az.rg.list(sub="subscription-id")
//	az.vm.list(sub="subscription-id", rg="resource-group")
//	az.vm.start(sub="subscription-id", rg="resource-group", name="vm-name")
//	az.vm.stop(sub="subscription-id", rg="resource-group", name="vm-name")
//	az.vm.deallocate(sub="subscription-id", rg="resource-group", name="vm-name")
//	az.vm.get(sub="subscription-id", rg="resource-group", name="vm-name")
//	az.storage.list_accounts(sub="subscription-id", rg="resource-group")
//	az.aks.list_clusters(sub="subscription-id", rg="resource-group")
//	az.aks.get_credentials(sub="subscription-id", rg="resource-group", name="cluster-name")
func SetupAzureAPI(env starlark.StringDict) {
	rgDict := starlark.NewDict(1)
	rgDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", azRGList))

	vmDict := starlark.NewDict(5)
	vmDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", azVMList))
	vmDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", azVMGet))
	vmDict.SetKey(starlark.String("start"), starlark.NewBuiltin("start", azVMStart))
	vmDict.SetKey(starlark.String("stop"), starlark.NewBuiltin("stop", azVMStop))
	vmDict.SetKey(starlark.String("deallocate"), starlark.NewBuiltin("deallocate", azVMDeallocate))

	storageDict := starlark.NewDict(1)
	storageDict.SetKey(starlark.String("list_accounts"), starlark.NewBuiltin("list_accounts", azStorageListAccounts))

	aksDict := starlark.NewDict(2)
	aksDict.SetKey(starlark.String("list_clusters"), starlark.NewBuiltin("list_clusters", azAKSListClusters))
	aksDict.SetKey(starlark.String("get_credentials"), starlark.NewBuiltin("get_credentials", azAKSGetCredentials))

	azDict := starlark.NewDict(4)
	azDict.SetKey(starlark.String("rg"), rgDict)
	azDict.SetKey(starlark.String("vm"), vmDict)
	azDict.SetKey(starlark.String("storage"), storageDict)
	azDict.SetKey(starlark.String("aks"), aksDict)
	env["az"] = azDict
}

func azCredential() (*azidentity.DefaultAzureCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("az: credential error: %v", err)
	}
	return cred, nil
}

// ── Resource Groups ───────────────────────────────────────────────────────────

func azRGList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armresources.NewResourceGroupsClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.rg.list: %v", err)
	}
	ctx := context.Background()
	pager := client.NewListPager(nil)
	result := starlark.NewList(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("az.rg.list: %v", err)
		}
		for _, rg := range page.Value {
			d := starlark.NewDict(4)
			if rg.Name != nil {
				d.SetKey(starlark.String("name"), starlark.String(*rg.Name))
			}
			if rg.Location != nil {
				d.SetKey(starlark.String("location"), starlark.String(*rg.Location))
			}
			if rg.ID != nil {
				d.SetKey(starlark.String("id"), starlark.String(*rg.ID))
			}
			if rg.Properties != nil && rg.Properties.ProvisioningState != nil {
				d.SetKey(starlark.String("provisioning_state"), starlark.String(*rg.Properties.ProvisioningState))
			}
			result.Append(d)
		}
	}
	return result, nil
}

// ── Virtual Machines ──────────────────────────────────────────────────────────

func azVMList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg?", &rg); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachinesClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.list: %v", err)
	}
	ctx := context.Background()
	result := starlark.NewList(nil)
	if rg != "" {
		pager := client.NewListPager(rg, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("az.vm.list: %v", err)
			}
			for _, vm := range page.Value {
				result.Append(azVMToDict(vm))
			}
		}
	} else {
		pager := client.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("az.vm.list: %v", err)
			}
			for _, vm := range page.Value {
				result.Append(azVMToDict(vm))
			}
		}
	}
	return result, nil
}

func azVMGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg", &rg, "name", &name); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachinesClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.get: %v", err)
	}
	resp, err := client.Get(context.Background(), rg, name, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.get: %v", err)
	}
	return azVMToDict(&resp.VirtualMachine), nil
}

func azVMStart(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg", &rg, "name", &name); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachinesClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.start: %v", err)
	}
	poller, err := client.BeginStart(context.Background(), rg, name, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.start: %v", err)
	}
	if _, err := poller.PollUntilDone(context.Background(), nil); err != nil {
		return nil, fmt.Errorf("az.vm.start: %v", err)
	}
	return starlark.None, nil
}

func azVMStop(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg", &rg, "name", &name); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachinesClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.stop: %v", err)
	}
	// PowerOff = OS shutdown but keeps billing; deallocate to stop billing
	poller, err := client.BeginPowerOff(context.Background(), rg, name, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.stop: %v", err)
	}
	if _, err := poller.PollUntilDone(context.Background(), nil); err != nil {
		return nil, fmt.Errorf("az.vm.stop: %v", err)
	}
	return starlark.None, nil
}

func azVMDeallocate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg", &rg, "name", &name); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachinesClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.deallocate: %v", err)
	}
	poller, err := client.BeginDeallocate(context.Background(), rg, name, nil)
	if err != nil {
		return nil, fmt.Errorf("az.vm.deallocate: %v", err)
	}
	if _, err := poller.PollUntilDone(context.Background(), nil); err != nil {
		return nil, fmt.Errorf("az.vm.deallocate: %v", err)
	}
	return starlark.None, nil
}

func azVMToDict(vm *armcompute.VirtualMachine) *starlark.Dict {
	d := starlark.NewDict(6)
	if vm.Name != nil {
		d.SetKey(starlark.String("name"), starlark.String(*vm.Name))
	}
	if vm.Location != nil {
		d.SetKey(starlark.String("location"), starlark.String(*vm.Location))
	}
	if vm.ID != nil {
		d.SetKey(starlark.String("id"), starlark.String(*vm.ID))
	}
	if vm.Properties != nil {
		if vm.Properties.HardwareProfile != nil && vm.Properties.HardwareProfile.VMSize != nil {
			d.SetKey(starlark.String("size"), starlark.String(string(*vm.Properties.HardwareProfile.VMSize)))
		}
		if vm.Properties.ProvisioningState != nil {
			d.SetKey(starlark.String("provisioning_state"), starlark.String(*vm.Properties.ProvisioningState))
		}
		if vm.Properties.StorageProfile != nil &&
			vm.Properties.StorageProfile.ImageReference != nil &&
			vm.Properties.StorageProfile.ImageReference.Offer != nil {
			d.SetKey(starlark.String("image_offer"), starlark.String(*vm.Properties.StorageProfile.ImageReference.Offer))
		}
	}
	return d
}

// ── Storage Accounts ─────────────────────────────────────────────────────────

func azStorageListAccounts(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg?", &rg); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armstorage.NewAccountsClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.storage.list_accounts: %v", err)
	}
	ctx := context.Background()
	result := starlark.NewList(nil)
	if rg != "" {
		pager := client.NewListByResourceGroupPager(rg, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("az.storage.list_accounts: %v", err)
			}
			for _, acct := range page.Value {
				result.Append(azStorageAccountToDict(acct))
			}
		}
	} else {
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("az.storage.list_accounts: %v", err)
			}
			for _, acct := range page.Value {
				result.Append(azStorageAccountToDict(acct))
			}
		}
	}
	return result, nil
}

func azStorageAccountToDict(acct *armstorage.Account) *starlark.Dict {
	d := starlark.NewDict(4)
	if acct.Name != nil {
		d.SetKey(starlark.String("name"), starlark.String(*acct.Name))
	}
	if acct.Location != nil {
		d.SetKey(starlark.String("location"), starlark.String(*acct.Location))
	}
	if acct.ID != nil {
		d.SetKey(starlark.String("id"), starlark.String(*acct.ID))
	}
	if acct.Kind != nil {
		d.SetKey(starlark.String("kind"), starlark.String(string(*acct.Kind)))
	}
	return d
}

// ── AKS ──────────────────────────────────────────────────────────────────────

func azAKSListClusters(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg?", &rg); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcontainerservice.NewManagedClustersClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.aks.list_clusters: %v", err)
	}
	ctx := context.Background()
	result := starlark.NewList(nil)
	if rg != "" {
		pager := client.NewListByResourceGroupPager(rg, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("az.aks.list_clusters: %v", err)
			}
			for _, c := range page.Value {
				result.Append(azAKSClusterToDict(c))
			}
		}
	} else {
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("az.aks.list_clusters: %v", err)
			}
			for _, c := range page.Value {
				result.Append(azAKSClusterToDict(c))
			}
		}
	}
	return result, nil
}

func azAKSGetCredentials(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sub, rg, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "sub", &sub, "rg", &rg, "name", &name); err != nil {
		return nil, err
	}
	cred, err := azCredential()
	if err != nil {
		return nil, err
	}
	client, err := armcontainerservice.NewManagedClustersClient(sub, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("az.aks.get_credentials: %v", err)
	}
	resp, err := client.ListClusterUserCredentials(context.Background(), rg, name, nil)
	if err != nil {
		return nil, fmt.Errorf("az.aks.get_credentials: %v", err)
	}
	result := starlark.NewList(nil)
	for _, kc := range resp.Kubeconfigs {
		d := starlark.NewDict(2)
		if kc.Name != nil {
			d.SetKey(starlark.String("name"), starlark.String(*kc.Name))
		}
		if kc.Value != nil {
			d.SetKey(starlark.String("kubeconfig"), starlark.String(string(kc.Value)))
		}
		result.Append(d)
	}
	return result, nil
}

func azAKSClusterToDict(c *armcontainerservice.ManagedCluster) *starlark.Dict {
	d := starlark.NewDict(6)
	if c.Name != nil {
		d.SetKey(starlark.String("name"), starlark.String(*c.Name))
	}
	if c.Location != nil {
		d.SetKey(starlark.String("location"), starlark.String(*c.Location))
	}
	if c.ID != nil {
		d.SetKey(starlark.String("id"), starlark.String(*c.ID))
	}
	if c.Properties != nil {
		if c.Properties.KubernetesVersion != nil {
			d.SetKey(starlark.String("kubernetes_version"), starlark.String(*c.Properties.KubernetesVersion))
		}
		if c.Properties.ProvisioningState != nil {
			d.SetKey(starlark.String("provisioning_state"), starlark.String(*c.Properties.ProvisioningState))
		}
		if c.Properties.PowerState != nil && c.Properties.PowerState.Code != nil {
			d.SetKey(starlark.String("power_state"), starlark.String(string(*c.Properties.PowerState.Code)))
		}
	}
	return d
}
