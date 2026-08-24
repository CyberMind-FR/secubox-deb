require ["fileinto", "mailbox"];
# Rspamd marque le spam via l'en-tête X-Spam ; on le range dans Junk plutôt
# que de le rejeter (le membre garde la main). Idempotent, global, par défaut.
if header :contains "X-Spam" "Yes" {
    fileinto :create "Junk";
    stop;
}
