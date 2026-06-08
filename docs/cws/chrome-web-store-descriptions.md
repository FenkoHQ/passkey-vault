# Chrome Web Store Descriptions

Paste-ready listing copy for the locales currently present in `src/_locales`.

## English (`en`)

### Summary

Store WebAuthn passkeys and TOTP 2FA codes locally. One searchable vault, optional PIN lock, encrypted sync, no cloud account.

### Detailed Description

Passkey Vault keeps your WebAuthn passkeys and your TOTP two-factor codes on your own device, in one place. No cloud account, and no third party holding your keys.

It intercepts WebAuthn sign-up and sign-in requests so you can create, store, search, and reuse passkeys directly, and it doubles as a 2FA authenticator for the one-time codes you would otherwise keep in a separate app.

What you can do:

- Keep passkeys and 2FA codes in one searchable vault, filtered by type
- Generate TOTP codes locally (RFC 6238) with a live countdown and click-to-copy
- Add codes by pasting an otpauth:// link, a QR screenshot, or a QR image; decoded on your device, with no camera permission
- Lock the vault behind an optional PIN that encrypts it at rest
- Back up everything to an encrypted file, or sync across devices over an end-to-end encrypted channel with no account
- Fall back to the browser and OS passkey UI for sites you have not saved, with per-site interception controls
- Inspect storage, sync logs, and WebAuthn events with the built-in developer tools

Your keys never leave your device unless you export or sync them, and sync is end-to-end encrypted, so the relays never see plaintext. There is no recovery if you lose every device and backup, so keep an offline backup.

Passkey Vault is a local-first tool aimed at developers, testers, and advanced users. Private keys and 2FA secrets live in local browser storage; treat the extension data and exported backups as sensitive credential material.

## French (`fr`)

### Summary

Stockez et utilisez des passkeys WebAuthn localement, avec sauvegarde, synchronisation et contrôles de repli du navigateur.

### Detailed Description

Passkey Vault est un outil de passkeys WebAuthn local-first pour les développeurs, les testeurs et les utilisateurs avancés qui veulent contrôler directement la création, le stockage, la sauvegarde, la synchronisation et le comportement de repli du navigateur.

L'extension intercepte les demandes d'inscription et de connexion WebAuthn, stocke les passkeys dans le stockage local de l'extension du navigateur, et vous permet d'inspecter, rechercher, exporter, importer et synchroniser des identifiants sans dépendre d'un compte cloud tiers.

Fonctionnalités principales :

- Coffre local pour les flux WebAuthn create et get
- Authentificateur TOTP / 2FA intégré (RFC 6238) avec codes en direct, copie et import otpauth:// / image QR
- Code PIN principal optionnel qui chiffre le coffre au repos et verrouille la popup
- Repli vers l'interface passkey du navigateur et du système lorsqu'aucune entrée correspondante n'existe dans le coffre
- Modes d'interception désactivé, tous les sites et liste d'autorisation
- Popup consultable avec thèmes clair et sombre
- Sauvegarde et import pour déplacer les passkeys entre environnements
- Synchronisation multi-appareils optionnelle avec une chaîne de synchronisation chiffrée basée sur Nostr
- Journalisation développeur, inspection du stockage, journaux de synchronisation et outils d'événements WebAuthn

Important : Passkey Vault est un outil de recherche et de développement. Les clés privées sont stockées dans le stockage local de l'extension du navigateur. Traitez les données de l'extension et les sauvegardes exportées comme des informations d'identification sensibles.

## Spanish (`es`)

### Summary

Guarda y usa passkeys WebAuthn localmente, con copias de seguridad, sincronización y controles de reserva del navegador.

### Detailed Description

Passkey Vault es una herramienta local-first para passkeys WebAuthn, pensada para desarrolladores, testers y usuarios avanzados que quieren controlar directamente la creación, el almacenamiento, las copias de seguridad, la sincronización y el comportamiento de reserva del navegador.

La extensión intercepta solicitudes de registro e inicio de sesión WebAuthn, guarda las passkeys en el almacenamiento local de la extensión del navegador y permite inspeccionar, buscar, exportar, importar y sincronizar credenciales sin depender de una cuenta en la nube de terceros.

Funciones principales:

- Bóveda local para flujos WebAuthn create y get
- Autenticador TOTP / 2FA integrado (RFC 6238) con códigos en vivo, copia e importación otpauth:// / imagen QR
- PIN maestro opcional que cifra la bóveda en reposo y bloquea el popup
- Reserva hacia la interfaz de passkeys del navegador y del sistema cuando no existe una entrada coincidente en la bóveda
- Modos de interceptación desactivado, todos los sitios y lista permitida
- Popup con búsqueda y temas claro y oscuro
- Copia de seguridad e importación para mover passkeys entre entornos
- Sincronización opcional entre dispositivos mediante una cadena de sincronización cifrada basada en Nostr
- Registros para desarrolladores, inspección de almacenamiento, registros de sincronización y herramientas de eventos WebAuthn

Importante: Passkey Vault es una herramienta de investigación y desarrollo. El material de clave privada se almacena en el almacenamiento local de la extensión del navegador. Trata los datos de la extensión y las copias de seguridad exportadas como material de credenciales sensible.

## Arabic (`ar`)

### Summary

خزّن واستخدم مفاتيح مرور WebAuthn محلياً، مع النسخ الاحتياطي والمزامنة والتحكم في الرجوع إلى المتصفح.

### Detailed Description

Passkey Vault هي أداة محلية أولاً لمفاتيح مرور WebAuthn، مخصصة للمطورين والمختبرين والمستخدمين المتقدمين الذين يريدون تحكماً مباشراً في إنشاء مفاتيح المرور وتخزينها ونسخها احتياطياً ومزامنتها وسلوك الرجوع إلى المتصفح.

تعترض الإضافة طلبات التسجيل وتسجيل الدخول عبر WebAuthn، وتخزن مفاتيح المرور في التخزين المحلي لإضافة المتصفح، وتتيح لك فحص بيانات الاعتماد والبحث فيها وتصديرها واستيرادها ومزامنتها دون الاعتماد على حساب سحابي تابع لطرف ثالث.

الميزات الرئيسية:

- خزنة محلية لتدفقات WebAuthn create و get
- مصادق TOTP / 2FA مدمج (RFC 6238) مع رموز حيّة ونسخ واستيراد otpauth:// / صورة QR
- رمز PIN رئيسي اختياري يشفّر الخزنة أثناء السكون ويقفل النافذة المنبثقة
- الرجوع إلى واجهة مفاتيح المرور في المتصفح ونظام التشغيل عند عدم وجود إدخال مطابق في الخزنة
- أوضاع اعتراض: معطل، كل المواقع، وقائمة السماح
- نافذة منبثقة قابلة للبحث مع وضعين فاتح وداكن
- نسخ احتياطي واستيراد لنقل مفاتيح المرور بين البيئات
- مزامنة اختيارية بين الأجهزة باستخدام سلسلة مزامنة مشفرة مبنية على Nostr
- سجلات للمطورين، فحص التخزين، سجلات المزامنة، وأدوات أحداث WebAuthn

مهم: Passkey Vault هي أداة بحث وتطوير. يتم تخزين مادة المفاتيح الخاصة في التخزين المحلي لإضافة المتصفح. تعامل مع بيانات الإضافة والنسخ الاحتياطية المصدّرة كمواد اعتماد حساسة.

## Persian (`fa`)

### Summary

کلیدهای عبور WebAuthn را به‌صورت محلی ذخیره و استفاده کنید؛ همراه با پشتیبان‌گیری، همگام‌سازی و کنترل‌های بازگشت مرورگر.

### Detailed Description

Passkey Vault یک ابزار محلی‌محور برای کلیدهای عبور WebAuthn است که برای توسعه‌دهندگان، آزمایش‌کنندگان و کاربران پیشرفته ساخته شده است؛ افرادی که می‌خواهند روی ایجاد، ذخیره‌سازی، پشتیبان‌گیری، همگام‌سازی و رفتار بازگشت مرورگر کنترل مستقیم داشته باشند.

این افزونه درخواست‌های ثبت‌نام و ورود WebAuthn را رهگیری می‌کند، کلیدهای عبور را در فضای ذخیره‌سازی محلی افزونه مرورگر نگه می‌دارد، و به شما امکان می‌دهد اعتبارنامه‌ها را بدون وابستگی به حساب ابری شخص ثالث بررسی، جستجو، صادر، وارد و همگام‌سازی کنید.

قابلیت‌های اصلی:

- خزانه محلی برای جریان‌های WebAuthn create و get
- احرازکننده TOTP / 2FA داخلی (RFC 6238) با کدهای زنده، کپی، و وارد کردن otpauth:// / تصویر QR
- پین اصلی اختیاری که خزانه را در حالت سکون رمزگذاری و پنجره بازشونده را قفل می‌کند
- بازگشت به رابط کلید عبور مرورگر و سیستم‌عامل زمانی که ورودی منطبقی در خزانه وجود ندارد
- حالت‌های رهگیری: غیرفعال، همه سایت‌ها و فهرست مجاز
- پنجره بازشونده قابل جستجو با پوسته روشن و تاریک
- پشتیبان‌گیری و وارد کردن برای جابه‌جایی کلیدهای عبور بین محیط‌ها
- همگام‌سازی اختیاری بین دستگاه‌ها با زنجیره همگام‌سازی رمزگذاری‌شده مبتنی بر Nostr
- گزارش‌های توسعه‌دهنده، بررسی ذخیره‌سازی، گزارش‌های همگام‌سازی و ابزارهای رویداد WebAuthn

مهم: Passkey Vault یک ابزار پژوهشی و توسعه‌ای است. داده‌های کلید خصوصی در فضای ذخیره‌سازی محلی افزونه مرورگر ذخیره می‌شود. داده‌های افزونه و پشتیبان‌های صادرشده را مانند اطلاعات اعتباری حساس مدیریت کنید.

## Russian (`ru`)

### Summary

Храните и используйте passkey WebAuthn локально, с резервными копиями, синхронизацией и управлением fallback браузера.

### Detailed Description

Passkey Vault — это local-first инструмент для passkey WebAuthn, предназначенный для разработчиков, тестировщиков и опытных пользователей, которым нужен прямой контроль над созданием, хранением, резервным копированием, синхронизацией и fallback-поведением браузера.

Расширение перехватывает запросы регистрации и входа WebAuthn, хранит passkey в локальном хранилище расширения браузера и позволяет просматривать, искать, экспортировать, импортировать и синхронизировать учетные данные без зависимости от стороннего облачного аккаунта.

Ключевые возможности:

- Локальное хранилище для потоков WebAuthn create и get
- Встроенный TOTP / 2FA аутентификатор (RFC 6238) с живыми кодами, копированием и импортом otpauth:// / QR-изображения
- Опциональный мастер-PIN, который шифрует хранилище и блокирует popup
- Fallback к интерфейсу passkey браузера и ОС, если в хранилище нет подходящей записи
- Режимы перехвата: отключено, все сайты и список разрешенных сайтов
- Popup с поиском и светлой/темной темой
- Резервное копирование и импорт для переноса passkey между средами
- Опциональная синхронизация между устройствами через зашифрованную sync-цепочку на основе Nostr
- Журналы для разработчиков, инспекция хранилища, журналы синхронизации и инструменты событий WebAuthn

Важно: Passkey Vault — это инструмент для исследований и разработки. Материал приватных ключей хранится в локальном хранилище расширения браузера. Относитесь к данным расширения и экспортированным резервным копиям как к чувствительным учетным данным.

## Chinese Simplified (`zh_CN`)

### Summary

在本地存储和使用 WebAuthn passkey，并支持备份、同步和浏览器回退控制。

### Detailed Description

Passkey Vault 是一款本地优先的 WebAuthn passkey 工具，面向开发者、测试人员和高级用户，适合需要直接控制 passkey 创建、存储、备份、同步以及浏览器回退行为的场景。

该扩展会拦截 WebAuthn 注册和登录请求，将 passkey 存储在浏览器扩展的本地存储中，并允许你检查、搜索、导出、导入和同步凭据，而无需依赖第三方云账号。

主要功能：

- 用于 WebAuthn create 和 get 流程的本地凭据库
- 内置 TOTP / 2FA 验证器（RFC 6238），支持实时验证码、复制以及 otpauth:// / 二维码图片导入
- 可选的主 PIN，可加密本地凭据库并锁定弹出窗口
- 当凭据库中没有匹配条目时，回退到浏览器和操作系统的 passkey 界面
- 支持关闭、所有网站和允许列表三种拦截模式
- 支持搜索的弹出窗口，并提供浅色和深色主题
- 通过备份和导入在不同环境之间移动 passkey
- 可选的跨设备同步，使用基于 Nostr 的加密同步链
- 开发者日志、存储检查、同步日志和 WebAuthn 事件工具

重要提示：Passkey Vault 是研究和开发工具。私钥材料存储在浏览器扩展的本地存储中。请将扩展数据和导出的备份视为敏感凭据材料处理。
