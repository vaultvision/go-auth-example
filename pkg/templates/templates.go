package templates

import (
	"embed"
	"html/template"
)

// Data is a type to use for template variables.
type Data map[string]interface{}

//go:embed *.html
var staticFs embed.FS

// New returns a new *html/template.Template containing all the templates
// within the templates directory.
func New() (*template.Template, error) {
	tpl, err := template.ParseFS(staticFs, "*.html")
	if err != nil {
		return nil, err
	}
	return tpl, nil
}
