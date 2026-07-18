package starlarkext

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"go.starlark.net/starlark"
)

// SetupK8sAPI registers the k8s.* namespace into the Starlark environment.
//
// Credentials: KUBECONFIG env var → ~/.kube/config → in-cluster config.
// All functions accept an optional kubeconfig="" keyword arg to override.
//
// Starlark API:
//
//	k8s.pods.list(ns="default", label="app=nginx")
//	k8s.pods.get(ns="default", name="pod-name")
//	k8s.pods.delete(ns="default", name="pod-name")
//	k8s.pods.logs(ns="default", name="pod-name", tail=100, container="")
//
//	k8s.deployments.list(ns="default", label="")
//	k8s.deployments.get(ns="default", name="dep-name")
//	k8s.deployments.scale(ns="default", name="dep-name", replicas=3)
//	k8s.deployments.restart(ns="default", name="dep-name")
//
//	k8s.services.list(ns="default")
//	k8s.services.get(ns="default", name="svc-name")
//
//	k8s.namespaces.list()
//	k8s.namespaces.create(name="my-ns")
//	k8s.namespaces.delete(name="my-ns")
//
//	k8s.configmaps.list(ns="default")
//	k8s.configmaps.get(ns="default", name="cm-name")
//	k8s.configmaps.create(ns="default", name="cm-name", data={"key":"val"})
//	k8s.configmaps.delete(ns="default", name="cm-name")
//
//	k8s.nodes.list()
//	k8s.events.list(ns="default")
func SetupK8sAPI(env starlark.StringDict) {
	podsDict := starlark.NewDict(4)
	_ = podsDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sPodsList))
	_ = podsDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", k8sPodsGet))
	_ = podsDict.SetKey(starlark.String("delete"), starlark.NewBuiltin("delete", k8sPodsDelete))
	_ = podsDict.SetKey(starlark.String("logs"), starlark.NewBuiltin("logs", k8sPodsLogs))

	deploymentsDict := starlark.NewDict(4)
	_ = deploymentsDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sDeploymentsList))
	_ = deploymentsDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", k8sDeploymentsGet))
	_ = deploymentsDict.SetKey(starlark.String("scale"), starlark.NewBuiltin("scale", k8sDeploymentsScale))
	_ = deploymentsDict.SetKey(starlark.String("restart"), starlark.NewBuiltin("restart", k8sDeploymentsRestart))

	servicesDict := starlark.NewDict(2)
	_ = servicesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sServicesList))
	_ = servicesDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", k8sServicesGet))

	namespacesDict := starlark.NewDict(3)
	_ = namespacesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sNamespacesList))
	_ = namespacesDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", k8sNamespacesCreate))
	_ = namespacesDict.SetKey(starlark.String("delete"), starlark.NewBuiltin("delete", k8sNamespacesDelete))

	configmapsDict := starlark.NewDict(4)
	_ = configmapsDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sConfigMapsList))
	_ = configmapsDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", k8sConfigMapsGet))
	_ = configmapsDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", k8sConfigMapsCreate))
	_ = configmapsDict.SetKey(starlark.String("delete"), starlark.NewBuiltin("delete", k8sConfigMapsDelete))

	nodesDict := starlark.NewDict(1)
	_ = nodesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sNodesList))

	eventsDict := starlark.NewDict(1)
	_ = eventsDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", k8sEventsList))

	k8sDict := starlark.NewDict(7)
	_ = k8sDict.SetKey(starlark.String("pods"), podsDict)
	_ = k8sDict.SetKey(starlark.String("deployments"), deploymentsDict)
	_ = k8sDict.SetKey(starlark.String("services"), servicesDict)
	_ = k8sDict.SetKey(starlark.String("namespaces"), namespacesDict)
	_ = k8sDict.SetKey(starlark.String("configmaps"), configmapsDict)
	_ = k8sDict.SetKey(starlark.String("nodes"), nodesDict)
	_ = k8sDict.SetKey(starlark.String("events"), eventsDict)
	env["k8s"] = k8sDict
}

// k8sClient builds a Kubernetes clientset. Priority: kubeconfig arg →
// KUBECONFIG env → ~/.kube/config → in-cluster config.
func k8sClient(kubeconfig string) (*kubernetes.Clientset, error) {
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	if kubeconfig == "" {
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("k8s: no kubeconfig found and not running in-cluster")
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: %v", err)
	}
	return cs, nil
}

// k8sUnpackCommon unpacks ns, name (optional), label (optional), kubeconfig (optional).
func k8sUnpackKubeconfig(kwargs []starlark.Tuple) string {
	for _, kv := range kwargs {
		if k, ok := starlark.AsString(kv[0]); ok && k == "kubeconfig" {
			if v, ok := starlark.AsString(kv[1]); ok {
				return v
			}
		}
	}
	return ""
}

// ── Pods ──────────────────────────────────────────────────────────────────────

func k8sPodsList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, label, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "label?", &label, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{LabelSelector: label})
	if err != nil {
		return nil, fmt.Errorf("k8s.pods.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, pod := range list.Items {
		_ = result.Append(k8sPodToDict(&pod))
	}
	return result, nil
}

func k8sPodsGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	pod, err := cs.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.pods.get: %v", err)
	}
	return k8sPodToDict(pod), nil
}

func k8sPodsDelete(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	if err := cs.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		return nil, fmt.Errorf("k8s.pods.delete: %v", err)
	}
	return starlark.None, nil
}

func k8sPodsLogs(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, container, kubeconfig string
	var tail = 100
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"ns?", &ns, "name", &name, "tail?", &tail, "container?", &container, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	tailLines := int64(tail)
	opts := &corev1.PodLogOptions{TailLines: &tailLines}
	if container != "" {
		opts.Container = container
	}
	rc, err := cs.CoreV1().Pods(ns).GetLogs(name, opts).Stream(context.Background())
	if err != nil {
		return nil, fmt.Errorf("k8s.pods.logs: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("k8s.pods.logs read: %v", err)
	}
	return starlark.String(string(data)), nil
}

func k8sPodToDict(pod *corev1.Pod) *starlark.Dict {
	d := starlark.NewDict(7)
	_ = d.SetKey(starlark.String("name"), starlark.String(pod.Name))
	_ = d.SetKey(starlark.String("namespace"), starlark.String(pod.Namespace))
	_ = d.SetKey(starlark.String("phase"), starlark.String(string(pod.Status.Phase)))
	_ = d.SetKey(starlark.String("node"), starlark.String(pod.Spec.NodeName))
	_ = d.SetKey(starlark.String("ip"), starlark.String(pod.Status.PodIP))
	containers := starlark.NewList(nil)
	for _, c := range pod.Spec.Containers {
		_ = containers.Append(starlark.String(c.Name))
	}
	_ = d.SetKey(starlark.String("containers"), containers)
	_ = d.SetKey(starlark.String("created_at"), starlark.String(pod.CreationTimestamp.UTC().Format(time.RFC3339)))
	return d
}

// ── Deployments ───────────────────────────────────────────────────────────────

func k8sDeploymentsList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, label, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "label?", &label, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.AppsV1().Deployments(ns).List(context.Background(), metav1.ListOptions{LabelSelector: label})
	if err != nil {
		return nil, fmt.Errorf("k8s.deployments.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, dep := range list.Items {
		d := starlark.NewDict(7)
		_ = d.SetKey(starlark.String("name"), starlark.String(dep.Name))
		_ = d.SetKey(starlark.String("namespace"), starlark.String(dep.Namespace))
		var desired int32
		if dep.Spec.Replicas != nil {
			desired = *dep.Spec.Replicas
		}
		_ = d.SetKey(starlark.String("replicas"), starlark.MakeInt64(int64(desired)))
		_ = d.SetKey(starlark.String("ready"), starlark.MakeInt64(int64(dep.Status.ReadyReplicas)))
		_ = d.SetKey(starlark.String("available"), starlark.MakeInt64(int64(dep.Status.AvailableReplicas)))
		_ = d.SetKey(starlark.String("updated"), starlark.MakeInt64(int64(dep.Status.UpdatedReplicas)))
		_ = d.SetKey(starlark.String("created_at"), starlark.String(dep.CreationTimestamp.UTC().Format(time.RFC3339)))
		_ = result.Append(d)
	}
	return result, nil
}

func k8sDeploymentsGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	dep, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.deployments.get: %v", err)
	}
	d := starlark.NewDict(7)
	_ = d.SetKey(starlark.String("name"), starlark.String(dep.Name))
	_ = d.SetKey(starlark.String("namespace"), starlark.String(dep.Namespace))
	var desired int32
	if dep.Spec.Replicas != nil {
		desired = *dep.Spec.Replicas
	}
	_ = d.SetKey(starlark.String("replicas"), starlark.MakeInt64(int64(desired)))
	_ = d.SetKey(starlark.String("ready"), starlark.MakeInt64(int64(dep.Status.ReadyReplicas)))
	_ = d.SetKey(starlark.String("available"), starlark.MakeInt64(int64(dep.Status.AvailableReplicas)))
	_ = d.SetKey(starlark.String("updated"), starlark.MakeInt64(int64(dep.Status.UpdatedReplicas)))
	// First container image
	if len(dep.Spec.Template.Spec.Containers) > 0 {
		_ = d.SetKey(starlark.String("image"), starlark.String(dep.Spec.Template.Spec.Containers[0].Image))
	}
	return d, nil
}

func k8sDeploymentsScale(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	var replicas int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"ns?", &ns, "name", &name, "replicas", &replicas, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	patch := fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas)
	_, err = cs.AppsV1().Deployments(ns).Patch(
		context.Background(), name,
		types.MergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("k8s.deployments.scale: %v", err)
	}
	return starlark.None, nil
}

func k8sDeploymentsRestart(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	patch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().UTC().Format(time.RFC3339),
	)
	_, err = cs.AppsV1().Deployments(ns).Patch(
		context.Background(), name,
		types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("k8s.deployments.restart: %v", err)
	}
	return starlark.None, nil
}

// ── Services ──────────────────────────────────────────────────────────────────

func k8sServicesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, label, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "label?", &label, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.CoreV1().Services(ns).List(context.Background(), metav1.ListOptions{LabelSelector: label})
	if err != nil {
		return nil, fmt.Errorf("k8s.services.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, svc := range list.Items {
		_ = result.Append(k8sSvcToDict(&svc))
	}
	return result, nil
}

func k8sServicesGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	svc, err := cs.CoreV1().Services(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.services.get: %v", err)
	}
	return k8sSvcToDict(svc), nil
}

func k8sSvcToDict(svc *corev1.Service) *starlark.Dict {
	d := starlark.NewDict(5)
	_ = d.SetKey(starlark.String("name"), starlark.String(svc.Name))
	_ = d.SetKey(starlark.String("namespace"), starlark.String(svc.Namespace))
	_ = d.SetKey(starlark.String("type"), starlark.String(string(svc.Spec.Type)))
	_ = d.SetKey(starlark.String("cluster_ip"), starlark.String(svc.Spec.ClusterIP))
	ports := starlark.NewList(nil)
	for _, p := range svc.Spec.Ports {
		pd := starlark.NewDict(3)
		_ = pd.SetKey(starlark.String("port"), starlark.MakeInt64(int64(p.Port)))
		_ = pd.SetKey(starlark.String("protocol"), starlark.String(string(p.Protocol)))
		_ = pd.SetKey(starlark.String("name"), starlark.String(p.Name))
		_ = ports.Append(pd)
	}
	_ = d.SetKey(starlark.String("ports"), ports)
	return d
}

// ── Namespaces ────────────────────────────────────────────────────────────────

func k8sNamespacesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.namespaces.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, ns := range list.Items {
		_ = result.Append(makeDict("name", ns.Name, "status", string(ns.Status.Phase)))
	}
	return result, nil
}

func k8sNamespacesCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if _, err := cs.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("k8s.namespaces.create: %v", err)
	}
	return starlark.None, nil
}

func k8sNamespacesDelete(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	if err := cs.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		return nil, fmt.Errorf("k8s.namespaces.delete: %v", err)
	}
	return starlark.None, nil
}

// ── ConfigMaps ────────────────────────────────────────────────────────────────

func k8sConfigMapsList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.CoreV1().ConfigMaps(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.configmaps.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, cm := range list.Items {
		_ = result.Append(makeDict("name", cm.Name, "namespace", cm.Namespace, "keys", keysOf(cm.Data)))
	}
	return result, nil
}

func k8sConfigMapsGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.configmaps.get: %v", err)
	}
	d := starlark.NewDict(3)
	_ = d.SetKey(starlark.String("name"), starlark.String(cm.Name))
	_ = d.SetKey(starlark.String("namespace"), starlark.String(cm.Namespace))
	data := starlark.NewDict(len(cm.Data))
	for k, v := range cm.Data {
		_ = data.SetKey(starlark.String(k), starlark.String(v))
	}
	_ = d.SetKey(starlark.String("data"), data)
	return d, nil
}

func k8sConfigMapsCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	var data *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"ns?", &ns, "name", &name, "data", &data, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	goData := map[string]string{}
	if data != nil {
		for _, kv := range data.Items() {
			k, ok1 := starlark.AsString(kv[0])
			v, ok2 := starlark.AsString(kv[1])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("k8s.configmaps.create: data keys and values must be strings")
			}
			goData[k] = v
		}
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       goData,
	}
	if _, err := cs.CoreV1().ConfigMaps(ns).Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("k8s.configmaps.create: %v", err)
	}
	return starlark.None, nil
}

func k8sConfigMapsDelete(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, name, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "name", &name, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	if err := cs.CoreV1().ConfigMaps(ns).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		return nil, fmt.Errorf("k8s.configmaps.delete: %v", err)
	}
	return starlark.None, nil
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

func k8sNodesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.nodes.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, node := range list.Items {
		ready := "Unknown"
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady {
				if cond.Status == corev1.ConditionTrue {
					ready = "Ready"
				} else {
					ready = "NotReady"
				}
			}
		}
		d := starlark.NewDict(5)
		_ = d.SetKey(starlark.String("name"), starlark.String(node.Name))
		_ = d.SetKey(starlark.String("status"), starlark.String(ready))
		_ = d.SetKey(starlark.String("version"), starlark.String(node.Status.NodeInfo.KubeletVersion))
		_ = d.SetKey(starlark.String("os"), starlark.String(node.Status.NodeInfo.OSImage))
		_ = d.SetKey(starlark.String("arch"), starlark.String(node.Status.NodeInfo.Architecture))
		_ = result.Append(d)
	}
	return result, nil
}

// ── Events ────────────────────────────────────────────────────────────────────

func k8sEventsList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ns, kubeconfig string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ns?", &ns, "kubeconfig?", &kubeconfig); err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	cs, err := k8sClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	list, err := cs.CoreV1().Events(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.events.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, ev := range list.Items {
		d := starlark.NewDict(6)
		_ = d.SetKey(starlark.String("name"), starlark.String(ev.InvolvedObject.Name))
		_ = d.SetKey(starlark.String("kind"), starlark.String(ev.InvolvedObject.Kind))
		_ = d.SetKey(starlark.String("reason"), starlark.String(ev.Reason))
		_ = d.SetKey(starlark.String("message"), starlark.String(ev.Message))
		_ = d.SetKey(starlark.String("type"), starlark.String(ev.Type))
		_ = d.SetKey(starlark.String("count"), starlark.MakeInt64(int64(ev.Count)))
		_ = result.Append(d)
	}
	return result, nil
}

// keysOf returns sorted keys of a map[string]string as a Go []string.
func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
