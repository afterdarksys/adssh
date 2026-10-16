//go:build unix

package sys

import (
	"net"
	"os/exec"
	"testing"
)

func TestSpawnSSHSessionPassesPluginDir(t *testing.T) {
	saveSpawnHooks(t)
	installSpawnFakes(t)
	id := "spawn-plugin"
	markSpawnSession(t, id, "bob", true)
	pty := openSpawnPTY(t)
	var got spawnSnap
	runSSHCommand = func(cmd *exec.Cmd) error {
		got = snapshotSpawn(cmd)
		return nil
	}
	SetSSHMonitorServer(func(net.Conn, string) {})
	if err := SpawnSSHSession(SSHSessionSpec{SessionID: id, User: "bob", PluginDir: "/srv/adssh/plugins", PTY: pty}); err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i+1 < len(got.args); i++ {
		if got.args[i] == "--plugin-dir" && got.args[i+1] == "/srv/adssh/plugins" {
			found = true
		}
	}
	if !found {
		t.Fatalf("args = %#v", got.args)
	}
	for _, bad := range []string{"relative/plugins", "/a\x00b", "-x"} {
		err := SpawnSSHSession(SSHSessionSpec{SessionID: id, User: "bob", PluginDir: bad, PTY: pty})
		assertSpawnErr(t, err, "adssh: ssh session: invalid value")
	}
}
