# Ori in Conduit

<p align="center"><img src="images/ori/hi.svg" width="180" alt="Ori waving hi"></p>

Ori is the little star from [Orbit](https://github.com/Elchi-dev/Orbit), the
Elchi mascot: a soft eight-point star with a ring, a moon on it and two
floating mitten hands. Conduit keeps its own control-room look in the app;
Ori is the companion in the docs.

In Conduit, Ori is your guide through the documentation. Every entry page
opens with Ori in the pose that fits what the page is about, so you can tell
at a glance whether you are about to set something up, read a spec or look
back at what was decided.

The pictures in `docs/images/ori` are Orbit's, used under its MIT licence.
They are drawn from Orbit's Ori component; see Orbit's `docs/ORI.md` for the
drawing rules.

## The poses

| | Pose | Shows on |
| --- | --- | --- |
| <img src="images/ori/hi.svg" width="72" alt=""> | `hi` | first steps: installing, contributing, this page |
| <img src="images/ori/working.svg" width="72" alt=""> | `working` | the architecture overview, the command line |
| <img src="images/ori/reading.svg" width="72" alt=""> | `reading` | the API, security |
| <img src="images/ori/thinking.svg" width="72" alt=""> | `thinking` | decisions, the protocol |
| <img src="images/ori/searching.svg" width="72" alt=""> | `searching` | the roadmap, self-hosting a hub |
| <img src="images/ori/writing.svg" width="72" alt=""> | `writing` | the build log |
| <img src="images/ori/planning.svg" width="72" alt=""> | `planning` | the guides |
| <img src="images/ori/drawing.svg" width="72" alt=""> | `drawing` | the architecture pages |
| <img src="images/ori/camera.svg" width="72" alt=""> | `camera` | backups |
| <img src="images/ori/helpers.svg" width="72" alt=""> | `helpers` | modules |
| <img src="images/ori/needs.svg" width="72" alt=""> | `needs` | free for a page about approvals |
| <img src="images/ori/done.svg" width="72" alt=""> | `done` | free for a page about a finished release |
| <img src="images/ori/idle.svg" width="72" alt=""> | `idle` | free |
| <img src="images/ori/sleeping.svg" width="72" alt=""> | `sleeping` | free |
| <img src="images/ori/oops.svg" width="72" alt=""> | `oops` | free for a troubleshooting page |

## Where Ori is

| Page | Pose |
| --- | --- |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | `hi` |
| [SECURITY.md](../SECURITY.md) | `reading` |
| [ARCHITECTURE.md](ARCHITECTURE.md) | `working` |
| [DECISIONS.md](DECISIONS.md) | `thinking` |
| [ROADMAP.md](ROADMAP.md) | `searching` |
| [BUILD_LOG.md](BUILD_LOG.md) | `writing` |
| [install.md](install.md) | `hi` |
| [cli.md](cli.md) | `working` |
| [backup.md](backup.md) | `camera` |
| [guides/](guides/README.md) | `planning` |
| [api/](api/README.md) | `reading` |
| [protocol/](protocol/README.md) | `thinking` |
| [self-hosting/](self-hosting/README.md) | `searching` |
| [modules/](modules/README.md) | `helpers` |
| [architecture/](architecture/README.md) | `drawing` |

## Adding Ori to a page

One line under the page's title, centered, 120 pixels wide, with an alt text
that says what Ori is doing. The path is relative to the page:

```html
<p align="center"><img src="images/ori/reading.svg" width="120" alt="Ori looking closely through a magnifying glass"></p>
```

From a folder inside `docs/`, start the path with `../images/ori/`; from the
repository root, with `docs/images/ori/`.
