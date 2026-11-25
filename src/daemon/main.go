// Command warden supervises one lab run. Both input sources feed the same analyzer.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const root = "/opt/warden"
const control = "/run/warden/lab.sock"

func dialLab(ctx context.Context) (net.Conn, error) {
	for {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", control)
		if err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("lab socket: %w", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// The greeting must originate from PID 1 in the shared lab PID namespace.
func verifyPeer(conn net.Conn) error {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("lab socket is not Unix")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var sockErr error
	if err = raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}
	if cred == nil || cred.Pid != 1 || cred.Uid != 65532 {
		return errors.New("control socket peer is not the bundled lab account at PID 1")
	}
	return nil
}

func labScope(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "SCOPE" {
		return "", errors.New("invalid lab greeting")
	}
	id, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || id == 0 {
		return "", errors.New("invalid lab cgroup")
	}
	return strconv.FormatUint(id, 10), nil
}

func startCapture(ctx context.Context, scope string, out io.Writer) (*exec.Cmd, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	cmd := exec.CommandContext(ctx, root+"/collector", scope)
	cmd.ExtraFiles = []*os.File{wr}
	cmd.Stdout, cmd.Stderr = out, os.Stderr
	err = cmd.Start()
	wr.Close()
	if err != nil {
		return nil, err
	}
	ready := make(chan error, 1)
	go func() {
		line, e := bufio.NewReader(rd).ReadString('\n')
		if e == nil && line != "READY\n" {
			e = errors.New("invalid probe readiness")
		}
		ready <- e
	}()
	select {
	case err = <-ready:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("probes failed before workload: %w", err)
	}
	return cmd, nil
}

func copyLab(r *bufio.Reader, dst io.Writer) error {
	for {
		// The actor's largest record is below 1 KiB. Refuse oversized lines.
		line, err := r.ReadSlice('\n')
		if err != nil {
			return err
		}
		if string(line) == "DONE\n" {
			return nil
		}
		if _, err = dst.Write(line); err != nil {
			return err
		}
	}
}

func run(mode string) error {
	source := "lab-witness"
	if mode == "live" {
		source = "kernel-ringbuf"
	} else if mode != "demo" {
		return errors.New("usage: warden demo|live")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	conn, err := dialLab(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = verifyPeer(conn); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	input := bufio.NewReaderSize(conn, 8192)
	line, err := input.ReadSlice('\n')
	if err != nil {
		return err
	}
	scope, err := labScope(string(line))
	if err != nil {
		return err
	}
	// Publish a run only after the sensor, analyzer and lab assertions succeed.
	dir, err := os.MkdirTemp("/report", ".pending-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	raw, err := os.Create(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return err
	}
	defer raw.Close()
	analyzer := exec.CommandContext(ctx, "python3", root+"/src/warden/analyze.py", "--source", source, "--out", dir)
	analyzer.Stdout, analyzer.Stderr = os.Stdout, os.Stderr
	stdin, err := analyzer.StdinPipe()
	if err != nil {
		return err
	}
	if err = analyzer.Start(); err != nil {
		return err
	}
	defer func() {
		if analyzer.ProcessState == nil {
			analyzer.Process.Kill()
			analyzer.Wait()
		}
	}()
	var sink io.Writer = io.MultiWriter(raw, stdin)
	var capture *exec.Cmd
	if mode == "live" {
		capture, err = startCapture(ctx, scope, sink)
		if err != nil {
			return err
		}
		defer func() {
			if capture.ProcessState == nil {
				capture.Process.Kill()
				capture.Wait()
			}
		}()
		sink = io.Discard // Only kernel records enter a live report.
	}
	if _, err = fmt.Fprintln(conn, "START"); err != nil {
		return err
	}
	if err = copyLab(input, sink); err != nil {
		return fmt.Errorf("incomplete workload: %w", err)
	}
	if capture != nil {
		if err = capture.Process.Signal(syscall.SIGTERM); err != nil {
			return err
		}
		if err = capture.Wait(); err != nil {
			return fmt.Errorf("capture or loss check: %w", err)
		}
	}
	if err = stdin.Close(); err != nil {
		return err
	}
	if err = analyzer.Wait(); err != nil {
		return err
	}
	if err = raw.Close(); err != nil {
		return err
	}
	check := exec.CommandContext(ctx, "python3", root+"/lab/verify.py", filepath.Join(dir, "incidents.json"), source)
	check.Stdout, check.Stderr = os.Stdout, os.Stderr
	if err = check.Run(); err != nil {
		return err
	}
	if _, err = fmt.Fprintln(conn, "ACK"); err != nil {
		return err
	}
	runName := "run-" + strings.TrimPrefix(filepath.Base(dir), ".pending-")
	if err = os.Rename(dir, filepath.Join("/report", runName)); err != nil {
		return err
	}
	link := filepath.Join("/report", "."+runName+"-link")
	if err = os.Symlink(runName, link); err != nil {
		return err
	}
	defer os.Remove(link)
	return os.Rename(link, "/report/latest")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: warden demo|live")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
