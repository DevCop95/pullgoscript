//go:build !windows

package persist

// Every backend is a no-op off Windows: the registry, the Task Scheduler and
// the WMI subscription store are Windows-only. List still returns an empty
// (non-nil) slice so the dashboard renders a clean "no footholds" table.

func listRun() []Entry     { return nil }
func listStartup() []Entry { return nil }
func listTasks() []Entry   { return nil }
func listWMI() []Entry     { return nil }

func addRun(Hive, string, string) error            { return nil }
func removeRun(Hive, string) error                 { return nil }
func addStartup(string, string) error              { return nil }
func removeStartup(string) error                   { return nil }
func addTask(string, string, string, string) error { return nil }
func removeTask(string) error                      { return nil }
func addWMI(string, string) error                  { return nil }
func removeWMI(string) error                       { return nil }
