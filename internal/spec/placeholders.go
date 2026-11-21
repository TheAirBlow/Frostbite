package spec

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// RemarkPlaceholders can be used in the remark of a host.
var RemarkPlaceholders = []string{
	"node", "country", "flag", "country_name", "inbound", "protocol", "transport", "security", "user", "host", "port",
}

// RouteNamePlaceholders can be used in the name of a Turnable destination. Each one may also carry an @ prefix, which
// takes the value from the inbound the destination leads to. "inbound_remark" is a deprecated alias of {@remark}.
var RouteNamePlaceholders = append(slices.Clone(RemarkPlaceholders), "remark", "inbound_remark", "route")

// RouteURLVars can be used in the custom link of a Turnable destination.
var RouteURLVars = append(slices.Clone(RouteNamePlaceholders), "uuid", "password", "name")

// {name} or {name:arg}: the arg is a language for country_name, upper or lower for the rest. {@name} looks the value
// up on the inbound a Turnable destination leads to.
var placeholder = regexp.MustCompile(`\{(@?)(\w*)(?::([\w-]*))?\}`)

// Placeholders holds the values a template fills in, by placeholder name. The flag and country names come from
// the "country" entry, a two letter code.
type Placeholders map[string]string

// Expand fills the placeholders of a template. One it doesn't know is left as written.
func (p Placeholders) Expand(tpl string) string {
	return p.expand(tpl, func(_, v string) string { return v })
}

// ExpandURL fills the placeholders of a link. Everything except host and port is escaped for a URL.
func (p Placeholders) ExpandURL(tpl string) string {
	return p.expand(tpl, func(key, v string) string {
		if name := strings.TrimPrefix(key, "@"); name == "host" || name == "port" {
			return v
		}
		return url.QueryEscape(v)
	})
}

func (p Placeholders) expand(tpl string, escape func(key, v string) string) string {
	return placeholder.ReplaceAllStringFunc(tpl, func(m string) string {
		sub := placeholder.FindStringSubmatch(m)
		key := sub[1] + sub[2]
		v, ok := p.value(key, sub[3])
		if !ok {
			return m
		}
		return escape(key, v)
	})
}

func (p Placeholders) value(key, arg string) (string, bool) {
	prefix := ""
	if rest, ok := strings.CutPrefix(key, "@"); ok {
		prefix, key = "@", rest
	}
	switch key {
	case "country_name":
		code, _ := p.get(prefix + "country")
		return CountryName(code, arg), true
	case "flag":
		code, _ := p.get(prefix + "country")
		return CountryFlag(code), true
	}
	v, ok := p.get(prefix + key)
	if !ok {
		return "", false
	}
	switch arg {
	case "":
		return v, true
	case "upper":
		return strings.ToUpper(v), true
	case "lower":
		return strings.ToLower(v), true
	}
	return "", false
}

// get returns the value of a name. An @ name without a value of its own falls back to the plain one.
func (p Placeholders) get(key string) (string, bool) {
	if v, ok := p[key]; ok {
		return v, true
	}
	if rest, ok := strings.CutPrefix(key, "@"); ok {
		v, ok := p[rest]
		return v, ok
	}
	return "", false
}

// CheckPlaceholders reports the first placeholder of a template that is not in allowed or has a wrong arg.
func CheckPlaceholders(tpl string, allowed []string) error {
	for _, m := range placeholder.FindAllStringSubmatch(tpl, -1) {
		key, arg := m[2], m[3]
		name := m[1] + key
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("unknown placeholder {%s}, use one of: {%s}", name, strings.Join(allowed, "}, {"))
		}
		switch {
		case key == "country_name":
			if arg != "" {
				if _, err := language.Parse(arg); err != nil {
					return fmt.Errorf("{%s:%s} needs a language code, like {country_name:ru}", name, arg)
				}
			}
		case key == "flag":
			if arg != "" {
				return fmt.Errorf("{%s} takes no argument", name)
			}
		case arg != "" && arg != "upper" && arg != "lower":
			return fmt.Errorf("{%s:%s}: use upper or lower after the colon", name, arg)
		}
	}
	return nil
}

// CountryFlag is the flag emoji of a two letter country code, or nothing for anything else.
func CountryFlag(code string) string {
	code = strings.ToUpper(code)
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return string([]rune{rune(code[0]-'A') + 0x1F1E6, rune(code[1]-'A') + 0x1F1E6})
}

// CountryName is the name of a two letter country code in a language, English when lang is empty or unknown.
// An unknown code comes back as it is.
func CountryName(code, lang string) string {
	region, err := language.ParseRegion(code)
	if err != nil {
		return code
	}
	tag, err := language.Parse(lang)
	if err != nil {
		tag = language.English
	}
	namer := display.Regions(tag)
	if namer == nil {
		namer = display.Regions(language.English)
	}
	if name := namer.Name(region); name != "" {
		return name
	}
	return code
}
