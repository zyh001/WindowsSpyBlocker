# Application

## Download

WindowsSpyBlocker is available on [GitHub releases]({{ config.repo_url }}releases/latest) page.

[Download WindowsSpyBlocker.exe]({{ config.repo_url }}releases/download/{{ git.tag | trim('v') }}/WindowsSpyBlocker.exe){: .md-button .md-button--primary }

But also:

* As a [Chocolatey package](https://chocolatey.org/packages/windowsspyblocker) that will allow you to benefit from automatic updates
* As a [Scoop](https://scoop.sh/) package (`windowsspyblocker`) that will allow you to benefit from automatic updates

## First launch

When you execute WindowsSpyBlocker for the first time, a configuration file named `app.conf` is generated:

![](../assets/app/root-folder.png)

This configuration file is especially necessary for people who want to contribute to the project through
the [Dev menu](dev/index.md).

## Usage

The application currently consists of two menus:

* [**Telemetry** - _Block telemetry and data collection_](telemetry/index.md)
* [**Dev** - _Several tools used by WindowsSpyBlocker_](dev/index.md)

![](../assets/app/menu.png)
