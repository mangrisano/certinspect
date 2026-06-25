# certinspect

Ispettore di certificati TLS da riga di comando.

Dato uno o più domini (o un file `.pem`/`.der`), mostra validità, giorni alla
scadenza, soggetto, issuer, SAN, algoritmo di firma, dimensione della chiave,
fingerprint SHA-256, flag CA, self-signed, eventuali debolezze crittografiche e
la corrispondenza dell'hostname.

## Requisiti

- Python >= 3.14

## Installazione (sviluppo)

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

## Uso

```bash
# Ispeziona un host
certinspect example.com

# Più host in una volta (modalità batch)
certinspect example.com github.com api.example.com

# Porta personalizzata
certinspect example.com --port 8443

# Output JSON (sempre una lista di oggetti)
certinspect example.com --json

# Ispeziona un certificato locale
certinspect --file ./certificato.pem

# Soglia di avviso scadenza personalizzata (default: 30 giorni)
certinspect example.com --days 14

# Salva il certificato scaricato in formato PEM
certinspect example.com --export ./scaricato.pem
```

## Opzioni

| Opzione         | Descrizione                                                    |
| --------------- | -------------------------------------------------------------- |
| `target...`     | Uno o più domini da ispezionare. Ometti quando usi `--file`.   |
| `--file PATH`   | Ispeziona un certificato locale (PEM o DER) invece di un host. |
| `--port N`      | Porta TCP a cui connettersi (default: 443).                    |
| `--json`        | Stampa il risultato come JSON invece del testo leggibile.      |
| `--days N`      | Avvisa se il certificato scade entro N giorni (default: 30).   |
| `--export PATH` | Salva il certificato ispezionato come file PEM in PATH.        |

## Exit code

Pensati per l'automazione (cron, CI, script di monitoraggio). In modalità batch
viene restituito il caso peggiore tra tutti i target.

| Code | Significato                                  |
| ---- | -------------------------------------------- |
| 0    | Certificato valido                           |
| 1    | Errore di runtime (rete, file, parsing)      |
| 2    | Errore negli argomenti della riga di comando |
| 3    | In scadenza entro la soglia `--days`         |
| 4    | Scaduto o con date non valide                |
| 5    | L'hostname non corrisponde al certificato    |

Esempio in uno script:

```bash
certinspect tuosito.it --days 21
case $? in
  0) ;;                                          # tutto ok
  3) echo "In scadenza" | mail -s "Avviso" tu@mail.it ;;
  4) echo "Scaduto"     | mail -s "Urgente" tu@mail.it ;;
  5) echo "Host errato" | mail -s "Urgente" tu@mail.it ;;
  *) echo "Check fallito" ;;
esac
```

## Sviluppo

```bash
# Test
pytest

# Lint e formattazione (Ruff)
ruff check src tests
ruff format src tests
```
