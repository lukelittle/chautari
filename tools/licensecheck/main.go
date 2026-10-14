/**
 * Copyright 2026 the original author or authors from the Chautari project.
 *
 * This file is part of the Chautari project, see https://github.com/lukelittle/chautari
 * for more information.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Command licensecheck verifies (or, with -fix, adds) the Apache 2.0 header
// on every source file.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const marker = "the original author or authors from the Chautari project"

var body = []string{
	"Copyright 2026 the original author or authors from the Chautari project.",
	"",
	"This file is part of the Chautari project, see https://github.com/lukelittle/chautari",
	"for more information.",
	"",
	`Licensed under the Apache License, Version 2.0 (the "License");`,
	"you may not use this file except in compliance with the License.",
	"You may obtain a copy of the License at",
	"",
	"     https://www.apache.org/licenses/LICENSE-2.0",
	"",
	"Unless required by applicable law or agreed to in writing, software",
	`distributed under the License is distributed on an "AS IS" BASIS,`,
	"WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
	"See the License for the specific language governing permissions and",
	"limitations under the License.",
}

// header renders the license block in a file type's comment syntax.
func header(ext string) string {
	var b strings.Builder
	switch ext {
	case ".go", ".js", ".css":
		b.WriteString("/**\n")
		for _, l := range body {
			if l == "" {
				b.WriteString(" *\n")
			} else {
				b.WriteString(" * " + l + "\n")
			}
		}
		b.WriteString(" */\n\n")
	case ".rego", ".sql", ".tf", ".sh", ".yml", ".yaml":
		prefix := "# "
		if ext == ".sql" {
			prefix = "-- "
		}
		for _, l := range body {
			b.WriteString(strings.TrimRight(prefix+l, " ") + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

var checked = map[string]bool{".go": true, ".js": true, ".css": true, ".rego": true, ".sql": true}

func main() {
	fix := flag.Bool("fix", false, "add missing headers")
	flag.Parse()
	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var missing []string
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules", "bin", "out", "templates":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(p)
		if !checked[ext] {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		head := string(b)
		if len(head) > 600 {
			head = head[:600]
		}
		if strings.Contains(head, marker) {
			return nil
		}
		if !*fix {
			missing = append(missing, p)
			return nil
		}
		return os.WriteFile(p, append([]byte(header(ext)), b...), 0o644)
	}
	for _, root := range roots {
		if err := filepath.WalkDir(root, walk); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "missing the Apache 2.0 license header (run: go run ./tools/licensecheck -fix):")
		for _, m := range missing {
			fmt.Fprintln(os.Stderr, "  "+m)
		}
		os.Exit(1)
	}
}
