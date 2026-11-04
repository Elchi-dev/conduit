# ComfyUI

A [ComfyUI](https://www.comfy.org/) server: GPU and memory, the queue,
recent generations with their prompts and output files, interrupting the
current generation, clearing what's waiting, and queueing a workflow
saved in a folder you choose.

**Setup.** Nothing for ComfyUI on the same machine
(`http://127.0.0.1:8188`). For another machine, its address, and a token
(in the vault) only if ComfyUI sits behind a proxy that asks for one.
ComfyUI itself has no sign-in, so don't expose it beyond your network. To
queue workflows, set **workflows folder** to the full path of a folder of
workflows saved in ComfyUI with Workflow, Export (API); leave it empty and
queueing stays off.

| Action | Risk | Notes |
| --- | --- | --- |
| `system_stats` | read | ComfyUI, Python and PyTorch versions, memory, and each GPU with graphics memory total and free. Not the server's command line. |
| `queue` | read | The running generation and the waiting ones, by number and prompt id, with their node counts. |
| `history` | read, sensitive | Recent generations (`limit`, 20 by default), newest first: status, start time and duration, the prompt texts of their text-encoding nodes, and output file names (temporary previews left out). Sensitive because prompts can be private: the audit log keeps only field names. |
| `workflows` | read | Files in the workflows folder, with size, date and whether each is usable (an Export (API) file) or why not. |
| `interrupt` | write | Stops the running generation (its partial result is lost); the queue carries on. On recent ComfyUI it names that prompt, so it can't stop the next one by accident. |
| `clear_queue` | destructive | Removes every waiting generation (not the running one). Preview lists them. |
| `queue_workflow` | destructive | Queues a `file` from the workflows folder, optionally with a new `seed` for every sampler. Preview lists the node count, the custom node packs it will run and any node the server lacks. |

**Why queueing is destructive, and only from a folder.** A ComfyUI
workflow runs every node in it, and custom nodes are Python code on the
server; some packs run shell commands or arbitrary code by design. So an
agent can never send a workflow of its own: it picks a file you saved in
the workflows folder, and the only change it can make is the seed (an
integer replacing existing integer seeds; links stay links). Even a file
you saved runs custom-node code and uses the GPU, so queueing it is
destructive and asks first under default policies. File names are plain
names ending in `.json`; the folder is opened with Go's `os.Root`, so
`..`, absolute paths and symlinks leading out of it are refused. Files in
the editor format, over 4 MB, or without a `class_type` on every node are
refused before anything reaches the server.

**Security.** The optional token goes in the `Authorization` header and
only to the configured address: redirects are followed within the same
host only. Outputs come from ComfyUI's own history; nothing is
downloaded.
