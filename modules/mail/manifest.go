package mail

import "github.com/elchi-dev/conduit/pkg/sdk"

const (
	selProps      = `"uid":{"type":"integer","description":"Message uid from a list or search"},"uids":{"type":"array","items":{"type":"integer"},"description":"Several messages at once"},"mailbox":{"type":"string","default":"INBOX"}`
	selSchema     = `{"type":"object","properties":{` + selProps + `}}`
	attachProp    = `"attachments":{"type":"array","description":"Files to attach","items":{"type":"object","properties":{"name":{"type":"string"},"path":{"type":"string","description":"Relative to this mailbox's attachments folder"},"base64":{"type":"string","description":"The content, base64-encoded"},"type":{"type":"string","description":"MIME type; guessed from the name if empty"}}}}`
	addrProps     = `"to":{"type":"array","items":{"type":"string"}},"cc":{"type":"array","items":{"type":"string"}},"bcc":{"type":"array","items":{"type":"string"}}`
	composeSchema = `{"type":"object","required":["to","subject","body"],"properties":{` + addrProps + `,
	"subject":{"type":"string"},
	"body":{"type":"string","x-multiline":true,"description":"Plain text"},
	"html":{"type":"string","x-multiline":true,"description":"Optional HTML version"},
	` + attachProp + `,
	"replyToUid":{"type":"integer","description":"Thread under this INBOX message (prefer reply)"}}}`
	replySchema = `{"type":"object","required":["uid","body"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"},
	"body":{"type":"string","x-multiline":true,"description":"Your reply, above the quoted message"},
	"html":{"type":"string","x-multiline":true},
	"cc":{"type":"array","items":{"type":"string"},"description":"Extra Cc"},"bcc":{"type":"array","items":{"type":"string"}},
	"quote":{"type":"boolean","default":true,"description":"Quote the original below your reply"},
	"draft":{"type":"boolean","description":"Save as a draft instead of sending"},
	` + attachProp + `}}`
	forwardSchema = `{"type":"object","required":["uid","to"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"},` + addrProps + `,
	"body":{"type":"string","x-multiline":true,"description":"A note above the forwarded message"},
	"includeAttachments":{"type":"boolean","default":true},
	"draft":{"type":"boolean","description":"Save as a draft instead of sending"},
	` + attachProp + `}}`
	updateDraftSchema = `{"type":"object","required":["uid"],"properties":{"uid":{"type":"integer","description":"Draft uid in the Drafts folder"},` + addrProps + `,
	"subject":{"type":"string"},"body":{"type":"string","x-multiline":true},"html":{"type":"string","x-multiline":true},
	` + attachProp + `,"keepAttachments":{"type":"boolean","default":true}}}`
	draftUID = `{"type":"object","required":["uid"],"properties":{"uid":{"type":"integer","description":"Draft uid in the Drafts folder"}}}`
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "mail", Name: "Mail", Version: "0.2.0", Category: "Communication", Icon: "mail",
		Description: "Any mailbox over IMAP and SMTP, including Proton Mail Bridge: read, search, thread, sort, label, reply, forward, send.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["email","password"],"properties":{
			"provider":{"type":"string","enum":["gmail","outlook","icloud","fastmail","yahoo","proton","other"],"default":"gmail","description":"Fills in the server settings below. Proton Mail Bridge: 127.0.0.1, STARTTLS, its certificate pinned."},
			"email":{"type":"string","description":"Your address"},
			"name":{"type":"string","description":"Name shown on mail you send"},
			"username":{"type":"string","description":"Login, if not your address"},
			"password":{"type":"string","x-secret":true,"description":"Vault reference to an app password, or the password Proton Mail Bridge shows for this account"},
			"imapHost":{"type":"string"},"imapPort":{"type":"integer"},
			"smtpHost":{"type":"string"},"smtpPort":{"type":"integer"},
			"security":{"type":"string","enum":["","tls","starttls","none"],"description":"Empty picks by port (993/465 TLS, others STARTTLS). None is allowed only to this machine."},
			"smtpSecurity":{"type":"string","enum":["","tls","starttls","none"],"description":"If SMTP differs from IMAP"},
			"tlsTrust":{"type":"string","enum":["","system","pinned"],"title":"Certificate trust","description":"System: certificate authorities. Pinned: one exact certificate, trusted on first use or given below (self-signed servers such as Proton Mail Bridge)."},
			"tlsCertificate":{"type":"string","x-multiline":true,"title":"Pinned certificate (PEM)","description":"Optional. In Proton Mail Bridge: Settings, Advanced settings, Export TLS certificates; paste cert.pem here."},
			"tlsFingerprint":{"type":"string","title":"Pinned SHA-256 fingerprint","description":"Optional instead of the certificate"},
			"serverSavesSent":{"type":"boolean","description":"The server files sent mail in Sent itself (Gmail, Outlook, Proton Bridge)"},
			"labelMode":{"type":"string","enum":["","folders","keywords"],"description":"How labels work: folders (Proton, Gmail) or IMAP keywords"},
			"labelPrefix":{"type":"string","description":"Folder that holds labels, e.g. Labels/ for Proton"},
			"attachmentsDir":{"type":"string","description":"Folder on this machine that attachments may be sent from by path"},
			"maxAttachmentMB":{"type":"integer","default":25,"maximum":50},
			"watch":{"type":"boolean","title":"Announce new mail","description":"Check regularly and publish events for automations, notifications and the brief"},
			"watchSeconds":{"type":"integer","default":120,"minimum":30,"title":"Check every (seconds)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "inbox", Title: "Inbox", Description: "Newest messages in a folder.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"mailbox":{"type":"string","default":"INBOX"},"limit":{"type":"integer","default":30,"maximum":200},"unreadOnly":{"type":"boolean"}}}`)},
			{Name: "search", Title: "Search", Description: "IMAP search; all given conditions must match.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"text":{"type":"string","description":"Words anywhere, headers included"},"body":{"type":"string","description":"Words in the body"},"from":{"type":"string"},"to":{"type":"string"},"cc":{"type":"string"},"subject":{"type":"string"},
				"since":{"type":"string","description":"YYYY-MM-DD"},"before":{"type":"string","description":"YYYY-MM-DD"},"sinceDays":{"type":"integer"},
				"unread":{"type":"boolean","description":"true: only unread; false: only read"},"flagged":{"type":"boolean"},"unreadOnly":{"type":"boolean"},
				"mailbox":{"type":"string","default":"INBOX"},"limit":{"type":"integer","default":50,"maximum":200}}}`)},
			{Name: "read", Title: "Read a message", Description: "Headers, text (HTML converted to text, never rendered), attachment list. Doesn't mark it read.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["uid"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"}}}`)},
			{Name: "thread", Title: "Conversation", Description: "Every message in the same thread (References and In-Reply-To), across this folder, Sent and Archive, oldest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["uid"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"}}}`)},
			{Name: "download_attachment", Title: "Download an attachment", Description: "One attachment's content as base64, up to maxMB.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["uid"],"properties":{"uid":{"type":"integer"},"mailbox":{"type":"string","default":"INBOX"},"index":{"type":"integer","description":"From read's attachment list"},"name":{"type":"string"},"maxMB":{"type":"integer","default":10,"maximum":25}}}`)},
			{Name: "mailboxes", Title: "Folders and labels", Description: "Every folder and label with message and unread counts and its role.", Risk: sdk.RiskRead},
			{Name: "unread_counts", Title: "Unread counts", Description: "Unread messages in the inbox and in every folder that has any.", Risk: sdk.RiskRead},
			{Name: "drafts", Title: "Drafts", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":30}}}`)},
			{Name: "mark_read", Title: "Mark read", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(selSchema)},
			{Name: "mark_unread", Title: "Mark unread", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(selSchema)},
			{Name: "flag", Title: "Flag", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(selSchema)},
			{Name: "unflag", Title: "Remove flag", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(selSchema)},
			{Name: "move", Title: "Move to folder", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["to"],"properties":{` + selProps + `,"to":{"type":"string","description":"Folder name, e.g. Archive or Folders/Receipts"}}}`)},
			{Name: "copy", Title: "Copy to folder", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["to"],"properties":{` + selProps + `,"to":{"type":"string"}}}`)},
			{Name: "archive", Title: "Archive", Description: "Move to the Archive folder.", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(selSchema)},
			{Name: "label", Title: "Add a label", Description: "Proton and Gmail: copies into the label's folder. Other servers: an IMAP keyword.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["label"],"properties":{` + selProps + `,"label":{"type":"string"},"create":{"type":"boolean","description":"Create the label if it doesn't exist"}}}`)},
			{Name: "unlabel", Title: "Remove a label", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["label"],"properties":{` + selProps + `,"label":{"type":"string"}}}`)},
			{Name: "delete", Title: "Delete", Description: "Moves to Trash (undo moves it back). In Trash, or with permanent, it is erased.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + selProps + `,"permanent":{"type":"boolean"}}}`)},
			{Name: "send", Title: "Send", Description: "Send a new message from this address. The preview shows recipients, subject and body.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(composeSchema)},
			{Name: "reply", Title: "Reply", Description: "Reply to the sender, threaded, with the original quoted.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true, Input: sdk.Schema(replySchema)},
			{Name: "reply_all", Title: "Reply all", Description: "Reply to the sender and everyone in To and Cc, except you.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true, Input: sdk.Schema(replySchema)},
			{Name: "forward", Title: "Forward", Description: "Forward with its attachments.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true, Input: sdk.Schema(forwardSchema)},
			{Name: "draft", Title: "Save a draft", Description: "Write a message into Drafts without sending it.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + addrProps + `,"subject":{"type":"string"},"body":{"type":"string","x-multiline":true},"html":{"type":"string"},` + attachProp + `}}`)},
			{Name: "update_draft", Title: "Update a draft", Description: "Change a draft; fields left out stay as they are.", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true, Input: sdk.Schema(updateDraftSchema)},
			{Name: "send_draft", Title: "Send a draft", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true, Input: sdk.Schema(draftUID)},
			{Name: "delete_draft", Title: "Delete a draft", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(draftUID)},
			{Name: "tls_status", Title: "Server certificates", Description: "The certificates the IMAP and SMTP servers present, and the pinned ones.", Risk: sdk.RiskRead},
			{Name: "trust_certificate", Title: "Trust a certificate", Description: "Pin a new certificate fingerprint (after Proton Bridge regenerated its certificate). Empty forgets the pin, so the next connection pins again. Destructive: it changes which certificate the mailbox trusts; the preview shows the old and new fingerprints.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"endpoint":{"type":"string","enum":["imap","smtp","both"],"default":"both"},"fingerprint":{"type":"string","description":"SHA-256, as tls_status shows it"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "message", Title: "Messages", ListAction: "inbox", GetAction: "read", ViewHint: "table"}},
		Events: []sdk.EventSpec{
			{Type: "mail.received", Description: "New messages arrived in the inbox (when Announce new mail is on)",
				Schema: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer"},"unread":{"type":"integer"},"messages":{"type":"array"}}}`)},
			{Type: "mail.unread", Description: "The inbox's unread count changed (when Announce new mail is on)",
				Schema: sdk.Schema(`{"type":"object","properties":{"unread":{"type":"integer"},"previous":{"type":"integer"}}}`)},
		},
	}
}
