# نصب و استفاده (فارسی)

## دامنهٔ پشتیبانی و ایمنی

نسخهٔ ۱ برای Ubuntu 22.04/24.04 با نصب استاندارد **x-ui** نوشته شده است:

- باینری Xray: `/usr/local/x-ui/bin/xray-linux-amd64`
- کانفیگ فعال: `/usr/local/x-ui/bin/config.json`
- دیتابیس x-ui: `/etc/x-ui/x-ui.db`
- access log: `/var/log/x-ui/access.log`
- RoutingService: `127.0.0.1:62789`

در کانفیگ فعال و template دیتابیس باید یک rule با `outboundTag: "direct"` وجود داشته باشد. نصب‌کننده اول این‌ها را فقط بررسی می‌کند. خود installer به x-ui یا Xray production restart/reload نمی‌دهد.

برای Shadow یک هویت WARP کاملاً تازه ساخته می‌شود. هیچ کلید، identity یا SOCKS مربوط به WARP production خوانده یا استفاده نمی‌شود. اگر bootstrap لازم باشد، برای WARP اصلی کاربر هم یک هویت دوم و مستقل ساخته می‌شود؛ هرگز از identity Shadow استفاده نمی‌شود.

## نصب تک‌دستوری

ابتدا مخزن را بررسی کنید، سپس این دستور را اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply
```

برای نصب در حالت مشاهده، بدون promotion زنده:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --dry-run
```

اگر مدیر پنل هنوز WARP خروجیِ کاربر را نساخته است، فقط در routing ساده می‌تواند bootstrap را صریحاً بخواهد:

```bash
curl -fsSL https://raw.githubusercontent.com/samanebdali/xray-auto-direct/main/install.sh | sudo bash -s -- --apply --bootstrap-primary-warp --inbound-tag YOUR_INBOUND_TAG
```

bootstrap یک WARP اصلی کاملاً جدا با tag `autodirect-primary-warp` می‌سازد، کانفیگ کامل را validate می‌کند، outbound و rules را زنده از طریق RoutingService اعمال می‌کند، همان تغییر را در template پایدار 3x-ui ذخیره می‌کند و PID Xray را بررسی می‌کند. اگر balancer، catch-all مبهم یا tag متداخل وجود داشته باشد، به‌جای تغییر حدسی متوقف می‌شود. اجرای مجدد آن idempotent است.

نصب‌کننده به‌صورت خودکار RoutingService و پیش‌نیازها را بررسی می‌کند، `wgcf` را دریافت می‌کند، یک WARP مستقل ثبت می‌کند (حداکثر پنج تلاش محدود)، Shadow SOCKS را فقط روی `127.0.0.1:20808` می‌سازد، کانفیگ را با همان Xray validate می‌کند، trace کلودفلر با `warp=on` یا `warp=plus` را تأیید می‌کند و بعد controller را فعال می‌کند.

اگر هر مرحله fail شود، نصب متوقف می‌شود؛ probe به WARP یا Direct production fallback نمی‌کند.

## policy قابل تنظیم

فایل زیر را ویرایش کنید و فقط controller را restart کنید:

```bash
sudoedit /etc/xray-auto-direct/policy.json
sudo systemctl restart xray-auto-direct.service
```

- `pinned_direct_suffixes`: هنگام start controller با Routing API به‌صورت زنده Direct می‌شوند.
- `manual_direct_suffixes`: برای دامنه‌هایی که خود کاربر صریحاً Direct می‌خواهد.
- `pinned_warp_suffixes`: هرگز probe یا promote نمی‌شوند و روی مسیر WARP از قبل تعریف‌شده می‌مانند.
- یک suffix نباید در هر دو لیست باشد. policy خراب fail-closed است: Direct جدید از policy اضافه نمی‌شود و استثناهای پیش‌فرض OpenAI روی WARP باقی می‌مانند.

تغییر policy، production Xray را restart نمی‌کند. قبل از هر تغییر زنده، controller کانفیگ موقت را validate و config/DB را backup می‌گیرد، routing rules را از طریق RoutingService اعمال می‌کند، PID production را می‌سنجد و در خطا rollback می‌کند.

## وضعیت و لاگ

```bash
sudo systemctl status xray-autodirect-shadow.service xray-auto-direct.service
sudo /usr/local/lib/xray-auto-direct/xray-auto-direct.py --selftest
sudo journalctl -u xray-auto-direct.service -u xray-autodirect-shadow.service -n 100 --no-pager
```

trace سالم Shadow باید `warp=on` یا `warp=plus` داشته باشد. خرابی Shadow باعث می‌شود همهٔ probe و promotionها متوقف شوند؛ ترافیک کاربر در مسیر production خودش باقی می‌ماند.

## توقف یا حذف امن

برای توقف اتوماسیون، بدون تغییر در Xray production:

```bash
sudo systemctl disable --now xray-auto-direct.service xray-autodirect-shadow.service
```

تا پیش از بررسی backupها، `/etc/xray-auto-direct` و `/var/lib/xray-auto-direct` را حذف نکنید. routeهایی که قبلاً promote شده‌اند عمداً باقی می‌مانند؛ حذف خودکارشان می‌تواند سایت در حال استفاده را خراب کند. backup هر تغییر زنده در `/var/lib/xray-auto-direct/backups` قرار دارد.

## امنیت

فایل‌های `shadow.json`، `wgcf-account.toml`، `wgcf-profile.conf`، `policy.json` و state را هرگز داخل Git قرار ندهید. پورت Shadow فقط روی loopback است و نباید در firewall باز شود.
