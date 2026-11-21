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

// RouteNamePlaceholders can be used in the name of a Turnable destination.
var RouteNamePlaceholders = append(slices.Clone(RemarkPlaceholders), "remark", "inbound_remark", "route")

// RouteURLVars can be used in the custom link of a Turnable destination.
var RouteURLVars = append(slices.Clone(RouteNamePlaceholders), "uuid", "password", "name")

// {name} or {name:arg}: the arg is a language for country_name, upper or lower for the rest.
var placeholder = regexp.MustCompile(`\{(\w*)(?::([\w-]*))?\}`)

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
		if key == "host" || key == "port" {
			return v
		}
		return url.QueryEscape(v)
	})
}

func (p Placeholders) expand(tpl string, escape func(key, v string) string) string {
	return placeholder.ReplaceAllStringFunc(tpl, func(m string) string {
		sub := placeholder.FindStringSubmatch(m)
		v, ok := p.value(sub[1], sub[2])
		if !ok {
			return m
		}
		return escape(sub[1], v)
	})
}

func (p Placeholders) value(key, arg string) (string, bool) {
	switch key {
	case "country_name":
		return CountryName(p["country"], arg), true
	case "flag":
		return CountryFlag(p["country"]), true
	}
	v, ok := p[key]
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

// CheckPlaceholders reports the first placeholder of a template that is not in allowed or has a wrong arg.
func CheckPlaceholders(tpl string, allowed []string) error {
	for _, m := range placeholder.FindAllStringSubmatch(tpl, -1) {
		key, arg := m[1], m[2]
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("unknown placeholder {%s}, use one of: {%s}", key, strings.Join(allowed, "}, {"))
		}
		switch {
		case key == "country_name":
			if arg != "" {
				if _, err := language.Parse(arg); err != nil {
					return fmt.Errorf("{country_name:%s} needs a language code, like {country_name:ru}", arg)
				}
			}
		case key == "flag":
			if arg != "" {
				return fmt.Errorf("{flag} takes no argument")
			}
		case arg != "" && arg != "upper" && arg != "lower":
			return fmt.Errorf("{%s:%s}: use upper or lower after the colon", key, arg)
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
