# certinspect — terminal demo (VHS tape)
# Regenerate with:  vhs docs/demo.tape   (run from the repo root)
# Requires: vhs (brew install vhs) and certinspect on PATH.

Output docs/demo.gif

Set Shell "zsh"
Set FontSize 16
Set Width 1200
Set Height 820
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 55ms

Hide
Type "clear" Enter
Show

Sleep 500ms
Type "certinspect github.com"
Sleep 800ms
Enter
Sleep 3500ms

Hide
Type "clear" Enter
Show

Sleep 400ms
Type "certinspect github.com pypi.org --field target --field days_to_expire"
Sleep 800ms
Enter
Sleep 3500ms
