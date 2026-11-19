---
name: Frostbite
description: Dark, cold, flat operator console for a VPN panel
colors:
  night-base: "oklch(21% 0.032 258)"
  night-surface: "oklch(17.5% 0.03 258)"
  night-edge: "oklch(14% 0.026 258)"
  frost-text: "oklch(92% 0.014 240)"
  ice-cyan: "oklch(79% 0.125 228)"
  ice-cyan-ink: "oklch(19% 0.04 245)"
  aurora-violet: "oklch(73% 0.14 288)"
  glacier-teal: "oklch(81% 0.115 182)"
  slate-neutral: "oklch(28% 0.03 258)"
  signal-success: "oklch(79% 0.15 160)"
  signal-warning: "oklch(83% 0.15 82)"
  signal-error: "oklch(71% 0.18 22)"
  signal-info: "oklch(78% 0.12 238)"
typography:
  display:
    fontFamily: "League Spartan, Jost, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.875rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "-0.025em"
  title:
    fontFamily: "League Spartan, Jost, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
  body:
    fontFamily: "Jost, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontFeature: "tnum"
  label:
    fontFamily: "Jost, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.75rem"
  mono:
    fontFamily: "ui-monospace, JetBrains Mono, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "0.75rem"
rounded:
  field: "0.6rem"
  box: "1rem"
  inner: "0.75rem"
  tile: "1rem"
  pill: "9999px"
spacing:
  gutter-mobile: "16px"
  gutter: "24px"
  card: "16px"
  inner: "12px"
components:
  button-primary:
    backgroundColor: "{colors.ice-cyan}"
    textColor: "{colors.ice-cyan-ink}"
    rounded: "{rounded.field}"
  button-ghost:
    textColor: "{colors.frost-text}"
    rounded: "{rounded.field}"
  card:
    backgroundColor: "{colors.night-surface}"
    rounded: "{rounded.box}"
    padding: "16px"
  card-inner:
    backgroundColor: "{colors.night-base}"
    rounded: "{rounded.inner}"
    padding: "12px"
  nav-rail:
    backgroundColor: "{colors.night-surface}"
    width: "80px"
---

# Design System: Frostbite

## Overview

**Creative North Star: "Frosted Control Room"**

A dark navy room with cold light. The page sits on three close navy tones, and a faint cyan-to-violet glow lies across the top of every screen. Color is held back for signal: the cyan primary action, status dots and semantic badges. Everything else is navy, frost-white text, and 1px edges.

The audience is expert operators, so density is high. Most text is 12–14px, numbers are tabular, and addresses are monospaced. The source of truth is the custom `frostbite` daisyUI theme in [the main stylesheet](frontend/app/assets/css/main.css). A light companion theme, `frost`, mirrors its roles, and operators can switch to any stock daisyUI theme. Because of that, components use theme roles and never hard-coded colors.

**Key Characteristics:**
- Three navy tones with 1px borders. No shadows on resting content.
- A single cyan primary action per view.
- League Spartan headings, Jost body, monospace for machine values.
- Copy is short. Details go in external docs.

## Colors

Cold and low-chroma at rest, with saturated color only where it means something.

### Primary
- **Ice Cyan** (ice-cyan): the one primary button in a view, the active nav item (at 15% fill), and focus. Text on it uses Ice Cyan Ink.

### Secondary
- **Aurora Violet** (aurora-violet): the far side of the top glow and of the logo gradient. It is not used for actions.

### Tertiary
- **Glacier Teal** (glacier-teal): an occasional accent for badges and charts.

### Neutral
- **Night Base** (night-base): the page background, and the inside of nested rows within cards.
- **Night Surface** (night-surface): cards, the nav rail and menus.
- **Night Edge** (night-edge): borders and dividers.
- **Frost Text** (frost-text): body text. Secondary text is 60% opacity, metadata 50%. Nothing below 50%: it fails 4.5:1.

### Named Rules
**The Signal Only Rule.** Saturated color means state or the primary action. A status is never shown by color alone. It also gets a label or a dot with a title.

**The Visible Affordance Rule.** An interactive control must stand out from the surface it sits on. The base layer in [the main stylesheet](frontend/app/assets/css/main.css) gives a plain `btn` a fill 12% lighter than base-200, so a neutral button stays visible on cards. Never put `bg-base-200` on a button. Add actions use `btn-soft btn-primary`. A ghost button is only for icon actions in a row or toolbar. Toggle chips and segmented controls show the selected state as `btn-soft btn-primary` and the rest as plain `btn`. Test: squint at the screen. If it reads as text, it's broken.

**The Theme Role Rule.** Use daisyUI roles (`primary`, `base-200`, `error`) and never literal colors, so every theme keeps working.

## Typography

**Display Font:** League Spartan (with Jost)
**Body Font:** Jost (with system-ui)
**Label/Mono Font:** ui-monospace stack

**Character:** League Spartan's geometric shapes on headings over Jost's clean body text. Tabular numbers are on globally.

### Hierarchy
- **Display** (600, 1.875rem, tight tracking): page titles only.
- **Title** (600, 1.25rem): card, drawer and section headings. Always `font-display`.
- **Body** (400, 0.875rem): forms, rows and descriptions.
- **Label** (0.75rem): metadata, badges and hints. Uppercase only for section labels.
- **Mono** (0.75rem): addresses, keys, tokens and anything a user copies.

### Named Rules
**The Short Copy Rule.** Helper text is one short line or it's left out. Protocol details, header names and crypto specifics (HMAC schemes, signature formats) go in external docs, linked with a "Docs" link. Don't explain trivial actions. A label like "Add webhook" needs no paragraph under it.

## Layout

- A desktop nav rail 80px wide on the left. On mobile it becomes a bottom tab bar with a blur, padded for the safe area.
- Content is capped at 1500px and centered.
- Side gutters are 16px on mobile and 24px from `sm` up.
- Editing happens in right-side drawers, not separate pages.
- One gap everywhere between panels: 16px (`gap-4`, `mt-4`, `mb-4`), horizontal and vertical, including tiles and cards inside a section.
- `scrollbar-gutter: stable` stops layout shift. Every layout must also work in RTL for Farsi.

## Elevation & Depth

The system is flat and uses tonal layers. daisyUI `--depth` is 0. Depth comes from the three navy tones and 1px borders.

### Shadow Vocabulary
- **Overlay** (`shadow-2xl`): drawers and modals.
- **Menu** (`shadow-xl`): dropdowns and the command palette.
- **Brand tile** (`shadow-lg shadow-primary/20`): the logo tile only.

### Named Rules
**The Float Only Rule.** Only things that float over the page cast a shadow: drawers, modals, menus and toasts. Cards, inputs and buttons never do.

## Shapes

- Corners are soft: 1rem for cards and boxes, 0.6rem for fields and buttons, 0.75rem for rows nested in a card, and fully round for badges and dots.
- Borders are always 1px Night Edge.

## Components

### Buttons
- **Shape:** field radius (0.6rem). `btn-sm` in forms and toolbars, `btn-xs` inside rows.
- **Primary:** Ice Cyan fill with Ice Cyan Ink text. One per view (page, drawer footer or modal). Empty-state and onboarding calls to action use `btn-soft btn-primary` when the page header already has the primary.
- **Secondary:** a plain `btn`, which has its own visible fill. Add actions are `btn-soft btn-primary`.
- **Rotations and other disruptive actions:** `btn-outline btn-warning`, grouped apart from routine actions.
- **Ghost:** icon-only (`btn-square`, `btn-circle`) in rows, toolbars and drawer headers.
- **Destructive:** go through ConfirmButton, styled as error.

### Chips / Badges
- `badge-sm`, soft or ghost. Warning-soft for things like a traffic multiplier, neutral for disabled, ghost for tags.

### Cards / Containers
- `.surface`: Night Surface background, Night Edge border, 1rem radius, 16px padding.
- Nested rows use Night Base, a border, 0.75rem radius and 12px padding.
- A `.surface` inside another `.surface` automatically gets a lighter tone (base-content mixed 5% into base-200) with a 10% border. Never nest two boxes of the same tone.
- A disabled item drops to 60% opacity.

### Inputs / Fields
- daisyUI inputs with no outline ring. Errors set `--input-color` to the error color through `[data-invalid]`.

### Navigation
- Rail items are icons in rounded tiles. The active item has a 15% primary fill and primary text.
- The gradient logo tile sits at the top. Search, settings and sign-out sit at the bottom.

### Status Dot
- A 10px round dot that pulses (ping) only while live. It is always paired with text or a title.

### Drawer
- Slides in from the right over a 55% black backdrop with a slight blur. It has a header (title and a 60% subtitle), optional tabs, a scrolling body, and a sticky footer padded for the safe area.

## Do's and Don'ts

### Do:
- **Do** use theme roles (`bg-base-200`, `text-primary`) so all themes keep working.
- **Do** make every button look like a button on its surface. On a card, use soft or outline buttons.
- **Do** use monospace and a CopyButton for addresses, keys and tokens.
- **Do** keep transitions between 120 and 180ms, and turn them off under `prefers-reduced-motion`.
- **Do** write labels and hints in one short line, and link to docs for specifics.

### Don't:
- **Don't** put a text-only ghost button or a `bg-base-200` button on a `.surface` card. It looks like a label.
- **Don't** put more than one `btn-primary` in a view.
- **Don't** put shadows on cards, inputs or resting content.
- **Don't** hard-code colors or use cyan or violet for decoration outside the glow and the logo.
- **Don't** write paragraphs explaining protocol internals, header names or signature schemes in the UI.
