require ["fileinto", "mailbox"];
# Rspamd (milter) ajoute « X-Spam-Status: Yes, score=… » au-dessus du seuil
# add_header. On range ces mails dans Junk plutôt que de les rejeter — le membre
# garde la main. Idempotent, global, par défaut.
if header :matches "X-Spam-Status" "Yes*" {
    fileinto :create "Junk";
    stop;
}
