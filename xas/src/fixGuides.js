// src/fixGuides.js

const FIX_GUIDES = {
  sql_injection: {
    severity: "critical",
    title: "SQL Injection",
    steps: [
      {
        title: "Parametreli sorgular kullanın",
        items: [
          "Prepared statements kullanın",
          "Bind parametreler ile kullanıcı girdisini ayırın"
        ]
      },
      {
        title: "ORM kullanın",
        items: [
          "Sequelize, Prisma, Hibernate, Entity Framework gibi ORM'ler kullanın"
        ]
      },
      {
        title: "Input validation uygulayın",
        items: [
          "Whitelist yaklaşımı kullanın",
          "Regex ile sadece beklenen karakterlere izin verin"
        ]
      }
    ],
    recommendation:
      "Kullanıcı girdisini asla doğrudan SQL sorgusunun içine string birleştirme ile eklemeyin."
  },

  command_injection: {
    severity: "critical",
    title: "Command Injection",
    steps: [
      {
        title: "Shell komutuna kullanıcı girdisi koymayın",
        items: [
          "exec('ping ' + userInput) gibi yapıları kullanmayın",
          "execFile veya parametre alan güvenli API'leri tercih edin"
        ]
      },
      {
        title: "Whitelist yaklaşımı uygulayın",
        items: [
          "Sadece önceden tanımlı komut veya parametreleri kabul edin"
        ]
      }
    ],
    recommendation:
      "Shell komutlarını minimuma indirin, mümkünse native API'ler üzerinden işlem yapın."
  },

  telnet: {
    severity: "high",
    title: "Telnet Service Açık",
    steps: [
      {
        title: "Telnet servisini kapatın (Linux)",
        items: [
          "sudo systemctl stop telnet",
          "sudo systemctl disable telnet"
        ]
      },
      {
        title: "Portu kapatın",
        items: [
          "sudo ufw deny 23",
          "Firewall üzerinde 23/TCP portunu engelleyin"
        ]
      }
    ],
    recommendation: "Telnet yerine SSH (22/TCP) kullanın, çünkü Telnet trafiği şifrelenmemiştir.",
    autoFix: {
      description: "23/TCP (Telnet) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block Telnet (23)" dir=in action=block protocol=TCP localport=23',
      linux: 'sudo ufw deny 23/tcp'
    },
    remediate: {
      os: "linux",
      needs: "systemd",
      description: "Telnet servisini durdurur ve devre dışı bırakır",
      backup: [],
      sudo: true,
      commands: [
        "systemctl stop telnet.socket 2>/dev/null || systemctl stop inetd 2>/dev/null || true",
        "systemctl disable telnet.socket 2>/dev/null || true"
      ],
      verify: [
        { command: "systemctl is-active telnet.socket 2>/dev/null || echo inactive", pass: "inactive|unknown|failed|no such" }
      ]
    }
  },

  ftp: {
    severity: "high",
    title: "FTP Service Açık",
    steps: [
      {
        title: "Anonymous erişimi kapatın",
        items: [
          "vsftpd.conf içinde anonymous_enable=NO ayarlayın",
          "Konfigürasyonu yeniden yükleyin: sudo systemctl restart vsftpd"
        ]
      },
      {
        title: "Güvenli alternatife geçin",
        items: [
          "Mümkünse SFTP (SSH üzerinden) veya FTPS kullanın"
        ]
      }
    ],
    recommendation:
      "FTP trafiği şifrelenmemiştir, hassas veriler için daima şifreli protokoller kullanın.",
    autoFix: {
      description: "21/TCP (FTP) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block FTP (21)" dir=in action=block protocol=TCP localport=21',
      linux: 'sudo ufw deny 21/tcp'
    },
    remediate: {
      os: "linux",
      needs: "systemd",
      description: "vsftpd anonim erişimini kapatır ve servisi yeniden başlatır",
      backup: ["/etc/vsftpd.conf"],
      sudo: true,
      commands: [
        "sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf",
        "systemctl restart vsftpd"
      ],
      verify: [
        { command: "grep -c '^anonymous_enable=NO' /etc/vsftpd.conf 2>/dev/null || echo 0", pass: "[1-9]" }
      ]
    }
  },

  rdp: {
    severity: "high",
    title: "RDP (3389/TCP) Açık",
    steps: [
      {
        title: "Sadece iç ağa açın",
        items: [
          "RDP'yi doğrudan internete açmayın",
          "VPN üzerinden erişim sağlayın"
        ]
      },
      {
        title: "NLA ve brute-force koruması",
        items: [
          "Network Level Authentication (NLA) etkinleştirin",
          "Hesap kilitleme politikaları ve brute-force koruması uygulayın"
        ]
      }
    ],
    recommendation:
      "RDP'yi mümkün olduğunca sınırlandırın ve mutlaka güçlü kimlik doğrulama uygulayın.",
    autoFix: {
      description: "3389/TCP (RDP) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block RDP (3389)" dir=in action=block protocol=TCP localport=3389',
      linux: 'sudo ufw deny 3389/tcp'
    }
  },

  xss: {
    severity: "medium",
    title: "Cross-Site Scripting (XSS)",
    steps: [
      {
        title: "Output encoding uygulayın",
        items: [
          "Kullanıcı girdisini HTML çıktısına koymadan önce encode edin",
          "Temel olarak <, >, ', \" karakterlerini escape edin"
        ]
      },
      {
        title: "CSP (Content Security Policy) ekleyin",
        items: [
          "default-src 'self' gibi bir politika ile dış script yüklemelerini kısıtlayın"
        ]
      }
    ],
    recommendation:
      "XSS açıkları kullanıcı oturumlarının ele geçirilmesine neden olabilir, tüm kullanıcı girdilerini sanitize edin."
  },

  csrf: {
    severity: "medium",
    title: "Cross-Site Request Forgery (CSRF)",
    steps: [
      {
        title: "CSRF token mekanizması ekleyin",
        items: [
          "Her state-changing istekte zorunlu token kullanın",
          "Token'ı session ile ilişkilendirin"
        ]
      },
      {
        title: "SameSite cookie özelliğini kullanın",
        items: [
          "Set-Cookie: ...; SameSite=Lax veya Strict kullanın"
        ]
      }
    ],
    recommendation:
      "Özellikle kritik işlemleri (şifre değişikliği, para transferi vb.) CSRF koruması olmadan bırakmayın."
  },

  // ──────────────── YENİ ZAFİYET TÜRLERİ ────────────────

  smb: {
    severity: "high",
    title: "SMB (445/TCP) Açık",
    steps: [
      {
        title: "SMB servisini kapatın veya kısıtlayın",
        items: [
          "Gereksiz SMB paylaşımlarını kaldırın",
          "SMBv1 protokolünü tamamen devre dışı bırakın",
          "Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false"
        ]
      },
      {
        title: "Firewall kuralları ekleyin",
        items: [
          "445/TCP portunu sadece güvenilir IP'lere açın",
          "İnternete açık SMB paylaşımı kesinlikle kapatın"
        ]
      },
      {
        title: "Güvenlik yamaları uygulayın",
        items: [
          "EternalBlue (MS17-010) gibi bilinen exploitler için yamaları kontrol edin",
          "Sistemi güncel tutun"
        ]
      }
    ],
    recommendation:
      "SMB portunu internete açmayın. EternalBlue gibi kritik exploitler bu port üzerinden çalışır.",
    autoFix: {
      description: "445/TCP (SMB) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block SMB (445)" dir=in action=block protocol=TCP localport=445',
      linux: 'sudo ufw deny 445/tcp'
    }
  },

  mysql: {
    severity: "high",
    title: "MySQL (3306/TCP) Açık",
    steps: [
      {
        title: "MySQL'i sadece localhost'a bağlayın",
        items: [
          "my.cnf: bind-address = 127.0.0.1",
          "Servisini yeniden başlatın: sudo systemctl restart mysql"
        ]
      },
      {
        title: "Uzak erişimi kısıtlayın",
        items: [
          "Root kullanıcısının uzak bağlantı yapamaması için: REVOKE ALL ON *.* FROM 'root'@'%'",
          "Sadece gerekli kullanıcılara belirli IP'lerden erişim verin"
        ]
      },
      {
        title: "Firewall kuralları",
        items: [
          "3306/TCP portunu sadece uygulama sunucusunun IP'sine açın"
        ]
      }
    ],
    recommendation:
      "Veritabanı portlarını asla doğrudan internete açmayın. SSH tüneli veya VPN kullanın.",
    autoFix: {
      description: "3306/TCP (MySQL) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block MySQL (3306)" dir=in action=block protocol=TCP localport=3306',
      linux: 'sudo ufw deny 3306/tcp'
    }
  },

  mssql: {
    severity: "high",
    title: "MSSQL (1433/TCP) Açık",
    steps: [
      {
        title: "SQL Server erişimini kısıtlayın",
        items: [
          "SQL Server Configuration Manager'dan sadece gerekli IP'lere izin verin",
          "Windows Firewall'da 1433/TCP kuralı oluşturun"
        ]
      },
      {
        title: "SA hesabını güvenli hale getirin",
        items: [
          "SA hesabını devre dışı bırakın veya çok güçlü şifre kullanın",
          "Windows Authentication modunu tercih edin"
        ]
      },
      {
        title: "Şifreli bağlantı zorunlu kılın",
        items: [
          "Force Encryption seçeneğini etkinleştirin",
          "TLS sertifikası tanımlayın"
        ]
      }
    ],
    recommendation:
      "MSSQL portunu internete açmayın. Brute-force saldırıları bu porta sıkça yapılır.",
    autoFix: {
      description: "1433/TCP (MSSQL) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block MSSQL (1433)" dir=in action=block protocol=TCP localport=1433',
      linux: 'sudo ufw deny 1433/tcp'
    }
  },

  ssh_weak: {
    severity: "medium",
    title: "SSH Zayıf Yapılandırma",
    steps: [
      {
        title: "Zayıf cipher ve algoritmaları devre dışı bırakın",
        items: [
          "sshd_config dosyasında: Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com",
          "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512",
          "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
        ]
      },
      {
        title: "Root login'i kapatın",
        items: [
          "PermitRootLogin no",
          "Key-based authentication kullanın: PasswordAuthentication no"
        ]
      },
      {
        title: "SSH versiyonunu kontrol edin",
        items: [
          "Yalnızca SSHv2 kullanın (Protocol 2)",
          "OpenSSH'ı güncel tutun"
        ]
      }
    ],
    recommendation:
      "SSH servisini en güncel yapılandırma standartlarına göre sıkılaştırın."
  },

  http_proxy: {
    severity: "medium",
    title: "HTTP Proxy (8080/TCP) Açık",
    steps: [
      {
        title: "Proxy erişimini kısıtlayın",
        items: [
          "Proxy'yi sadece iç ağda kullanılabilir hale getirin",
          "Kimlik doğrulama ekleyin"
        ]
      },
      {
        title: "Gereksizse kapatın",
        items: [
          "Kullanılmıyorsa proxy servisini durdurun",
          "Firewall'da 8080/TCP portunu engelleyin"
        ]
      }
    ],
    recommendation:
      "Açık proxy'ler saldırganlar tarafından anonim saldırı aracı olarak kullanılabilir."
  },

  directory_listing: {
    severity: "medium",
    title: "Directory Listing Açık",
    steps: [
      {
        title: "Apache'de kapatın",
        items: [
          "httpd.conf veya .htaccess: Options -Indexes",
          "Servisi yeniden başlatın"
        ]
      },
      {
        title: "Nginx'te kapatın",
        items: [
          "nginx.conf: autoindex off;",
          "sudo nginx -s reload"
        ]
      },
      {
        title: "IIS'te kapatın",
        items: [
          "IIS Manager → Directory Browsing → Disable"
        ]
      }
    ],
    recommendation:
      "Dizin listeleme, saldırganlara dosya yapınızı gösterir. Tüm web sunucularında kapatın."
  },

  admin_panel: {
    severity: "high",
    title: "Erişilebilir Yönetim Paneli",
    steps: [
      {
        title: "Paneli internete kapatın",
        items: [
          "Yönetim panelini yalnızca iç ağdan/VPN üzerinden erişilebilir yapın",
          "Firewall veya reverse proxy ile IP kısıtlaması (allowlist) uygulayın"
        ]
      },
      {
        title: "Kimlik doğrulamayı güçlendirin",
        items: [
          "Güçlü parola + çok faktörlü doğrulama (MFA) zorunlu kılın",
          "Varsayılan kullanıcı adı/parolaları (admin/admin) değiştirin",
          "Başarısız giriş denemelerine rate-limit / lockout ekleyin"
        ]
      },
      {
        title: "Varlığı gizleyin",
        items: [
          "Panel yolunu tahmin edilebilir adlardan (/admin, /wp-admin) değiştirin",
          "Dizin listelemeyi ve bilgilendirici hata mesajlarını kapatın"
        ]
      }
    ],
    recommendation:
      "İnternete açık yönetim panelleri kaba kuvvet ve varsayılan kimlik bilgisi saldırılarının ilk hedefidir. Erişimi ağ düzeyinde kısıtlayın."
  },

  ssl_expired: {
    severity: "high",
    title: "SSL/TLS Sertifika Sorunu",
    steps: [
      {
        title: "Sertifikayı yenileyin",
        items: [
          "Let's Encrypt kullanıyorsanız: sudo certbot renew",
          "Ticari sertifika ise sağlayıcınızdan yeni sertifika alın"
        ]
      },
      {
        title: "TLS yapılandırmasını sıkılaştırın",
        items: [
          "TLS 1.2 ve üzeri kullanın, TLS 1.0/1.1 kapatın",
          "ssl_protocols TLSv1.2 TLSv1.3; (Nginx)",
          "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 (Apache)"
        ]
      },
      {
        title: "HSTS header ekleyin",
        items: [
          "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ]
      }
    ],
    recommendation:
      "Geçersiz SSL sertifikaları MITM saldırılarına kapı açar. Sertifika otomasyonu kurun."
  },

  cors_misconfig: {
    severity: "medium",
    title: "CORS Yanlış Yapılandırma",
    steps: [
      {
        title: "Access-Control-Allow-Origin'i kısıtlayın",
        items: [
          "Wildcard (*) kullanmayın",
          "Sadece güvenilir origin'lere izin verin: Access-Control-Allow-Origin: https://yourdomain.com"
        ]
      },
      {
        title: "Credential'lı isteklerde dikkatli olun",
        items: [
          "Access-Control-Allow-Credentials: true ise wildcard origin kesinlikle kullanmayın",
          "Origin whitelist mekanizması kurun"
        ]
      }
    ],
    recommendation:
      "CORS yanlış yapılandırması, hassas verilerin yetkisiz domain'ler tarafından okunmasına yol açar."
  },

  missing_headers: {
    severity: "low",
    title: "Güvenlik Başlıkları Eksik",
    steps: [
      {
        title: "Temel güvenlik başlıklarını ekleyin",
        items: [
          "X-Content-Type-Options: nosniff",
          "X-Frame-Options: DENY veya SAMEORIGIN",
          "X-XSS-Protection: 1; mode=block",
          "Referrer-Policy: strict-origin-when-cross-origin"
        ]
      },
      {
        title: "Content Security Policy ekleyin",
        items: [
          "Content-Security-Policy: default-src 'self'; script-src 'self'",
          "İhtiyaçlarınıza göre policy'yi özelleştirin"
        ]
      },
      {
        title: "Permissions Policy ekleyin",
        items: [
          "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ]
      }
    ],
    recommendation:
      "Güvenlik başlıkları tarayıcı seviyesinde ek koruma sağlar. Tüm response'lara ekleyin."
  },

  open_redirect: {
    severity: "medium",
    title: "Açık Yönlendirme (Open Redirect)",
    steps: [
      {
        title: "Yönlendirme URL'lerini doğrulayın",
        items: [
          "Kullanıcı girdisinden gelen URL'leri doğrudan redirect'e kullanmayın",
          "Whitelist yaklaşımı: Sadece izin verilen domain'lere yönlendirin"
        ]
      },
      {
        title: "Göreceli URL kullanın",
        items: [
          "Tam URL yerine göreceli path kullanın: /dashboard vs https://evil.com",
          "URL'in sizin domain'inize ait olduğunu kontrol edin"
        ]
      }
    ],
    recommendation:
      "Open redirect, phishing saldırılarında güvenilir domain'inizi kullanarak kurbanları kandırmak için kullanılabilir."
  },

  weak_password: {
    severity: "high",
    title: "Zayıf Şifre Politikası",
    steps: [
      {
        title: "Güçlü şifre politikası uygulayın",
        items: [
          "Minimum 12 karakter zorunlu kılın",
          "Büyük/küçük harf, rakam ve özel karakter zorunluluğu",
          "Yaygın şifreleri (password123, admin vb.) engelleyin"
        ]
      },
      {
        title: "Ek güvenlik önlemleri",
        items: [
          "Çok faktörlü kimlik doğrulama (MFA/2FA) ekleyin",
          "Hesap kilitleme: 5 başarısız denemeden sonra geçici kilitleme",
          "Brute-force koruması için rate limiting uygulayın"
        ]
      }
    ],
    recommendation:
      "Zayıf şifreler en yaygın saldırı vektörüdür. MFA ile desteklenmiş güçlü şifre politikası zorunludur."
  },

  dns_zone_transfer: {
    severity: "high",
    title: "DNS Zone Transfer Açık",
    steps: [
      {
        title: "Zone transfer'i kısıtlayın",
        items: [
          "BIND: allow-transfer { trusted-servers; };",
          "Windows DNS: Zone Properties → Zone Transfers → Only to listed servers",
          "Sadece yetkili secondary DNS sunucularına izin verin"
        ]
      },
      {
        title: "DNSSEC etkinleştirin",
        items: [
          "DNS yanıtlarının bütünlüğünü doğrulamak için DNSSEC kullanın",
          "Zone signing yapılandırın"
        ]
      }
    ],
    recommendation:
      "Açık zone transfer, saldırganlara tüm DNS kayıtlarınızı ve altyapı bilgilerinizi ifşa eder."
  },

  vnc: {
    severity: "high",
    title: "VNC (5900/TCP) Açık",
    steps: [
      {
        title: "VNC erişimini kısıtlayın",
        items: [
          "VNC'yi doğrudan internete açmayın",
          "SSH tüneli üzerinden erişim sağlayın: ssh -L 5900:localhost:5900 user@server"
        ]
      },
      {
        title: "Güçlü şifre kullanın",
        items: [
          "VNC şifresini en az 8 karakterli, karmaşık yapın",
          "Mümkünse VNC yerine SSH + X11 forwarding kullanın"
        ]
      }
    ],
    recommendation:
      "VNC trafiği varsayılan olarak şifrelenmemiştir. SSH tüneli olmadan kullanmayın.",
    autoFix: {
      description: "5900/TCP (VNC) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block VNC (5900)" dir=in action=block protocol=TCP localport=5900',
      linux: 'sudo ufw deny 5900/tcp'
    }
  },

  redis: {
    severity: "high",
    title: "Redis (6379/TCP) Açık",
    steps: [
      {
        title: "Redis'i localhost'a bağlayın",
        items: [
          "redis.conf: bind 127.0.0.1",
          "protected-mode yes"
        ]
      },
      {
        title: "Şifre koruması ekleyin",
        items: [
          "redis.conf: requirepass <güçlü-şifre>",
          "Dangerous komutları devre dışı bırakın: rename-command FLUSHALL \"\""
        ]
      }
    ],
    recommendation:
      "Korumasız Redis sunucuları anında ele geçirilebilir. Asla internete açık bırakmayın.",
    autoFix: {
      description: "6379/TCP (Redis) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block Redis (6379)" dir=in action=block protocol=TCP localport=6379',
      linux: 'sudo ufw deny 6379/tcp'
    }
  },

  mongodb: {
    severity: "high",
    title: "MongoDB (27017/TCP) Açık",
    steps: [
      {
        title: "MongoDB'yi localhost'a bağlayın",
        items: [
          "mongod.conf: bindIp: 127.0.0.1",
          "Servisi yeniden başlatın"
        ]
      },
      {
        title: "Kimlik doğrulama etkinleştirin",
        items: [
          "mongod.conf: security.authorization: enabled",
          "Admin kullanıcısı oluşturun",
          "Uygulamalar için ayrı, kısıtlı yetkili kullanıcılar tanımlayın"
        ]
      }
    ],
    recommendation:
      "Kimlik doğrulaması olmayan MongoDB sunucuları, internetteki en yaygın hedeflerdendir.",
    autoFix: {
      description: "27017/TCP (MongoDB) portunu firewall üzerinden engeller.",
      windows: 'netsh advfirewall firewall add rule name="XAS: Block MongoDB (27017)" dir=in action=block protocol=TCP localport=27017',
      linux: 'sudo ufw deny 27017/tcp'
    }
  }
};

module.exports = {
  FIX_GUIDES
};