package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

type theme struct {
	bg        color.Color
	surface   color.Color
	surface2  color.Color
	border    color.Color
	primary   color.Color
	secondary color.Color
	text      color.Color
	muted     color.Color
	green     color.Color
	amber     color.Color
	red       color.Color

	app        lipgloss.Style
	header     lipgloss.Style
	brand      lipgloss.Style
	sidebar    lipgloss.Style
	nav        lipgloss.Style
	navActive  lipgloss.Style
	panel      lipgloss.Style
	panelTitle lipgloss.Style
	mutedText  lipgloss.Style
	statusOK   lipgloss.Style
	statusWarn lipgloss.Style
	statusBad  lipgloss.Style
	selected   lipgloss.Style
	modal      lipgloss.Style
	key        lipgloss.Style
}

func newTheme() theme {
	t := theme{
		bg:        lipgloss.Color("#0A0F1D"),
		surface:   lipgloss.Color("#11182A"),
		surface2:  lipgloss.Color("#172139"),
		border:    lipgloss.Color("#2A3858"),
		primary:   lipgloss.Color("#66E3D4"),
		secondary: lipgloss.Color("#A78BFA"),
		text:      lipgloss.Color("#E8EEF8"),
		muted:     lipgloss.Color("#8190AA"),
		green:     lipgloss.Color("#6ED59A"),
		amber:     lipgloss.Color("#F3C969"),
		red:       lipgloss.Color("#FF7188"),
	}
	t.app = lipgloss.NewStyle().Background(t.bg).Foreground(t.text)
	t.header = lipgloss.NewStyle().Background(t.surface).Foreground(t.text).Padding(0, 1)
	t.brand = lipgloss.NewStyle().Foreground(t.primary).Bold(true)
	t.sidebar = lipgloss.NewStyle().Background(t.surface).Foreground(t.muted).Padding(1, 1).BorderRight(true).BorderForeground(t.border)
	t.nav = lipgloss.NewStyle().Foreground(t.muted).Padding(0, 1)
	t.navActive = lipgloss.NewStyle().Background(t.surface2).Foreground(t.primary).Bold(true).Padding(0, 1)
	t.panel = lipgloss.NewStyle().Background(t.surface).Foreground(t.text).Border(lipgloss.RoundedBorder()).BorderForeground(t.border).Padding(0, 1)
	t.panelTitle = lipgloss.NewStyle().Foreground(t.primary).Bold(true)
	t.mutedText = lipgloss.NewStyle().Foreground(t.muted)
	t.statusOK = lipgloss.NewStyle().Foreground(t.green).Bold(true)
	t.statusWarn = lipgloss.NewStyle().Foreground(t.amber).Bold(true)
	t.statusBad = lipgloss.NewStyle().Foreground(t.red).Bold(true)
	t.selected = lipgloss.NewStyle().Background(t.surface2).Foreground(t.text)
	t.modal = lipgloss.NewStyle().Background(t.surface).Foreground(t.text).Border(lipgloss.DoubleBorder()).BorderForeground(t.secondary).Padding(1, 2)
	t.key = lipgloss.NewStyle().Background(t.surface2).Foreground(t.primary).Padding(0, 1)
	return t
}
