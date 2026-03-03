const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, HeadingLevel,
  BorderStyle, WidthType, ShadingType, PageNumber, PageBreak,
  TabStopType, TabStopPosition, ImageRun
} = require("docx");

// ─── Color palette ───
const C = {
  primary: "1B2A4A",    // dark navy
  accent: "2E86AB",     // teal blue
  accent2: "E8505B",    // coral red
  bg: "F0F4F8",         // light gray
  bgDark: "1B2A4A",     // navy bg
  white: "FFFFFF",
  black: "000000",
  gray: "666666",
  grayLight: "AAAAAA",
  grayBorder: "D0D5DD",
  green: "27AE60",
  orange: "F39C12",
  red: "E74C3C",
  yellow: "F1C40F",
};

const border = { style: BorderStyle.SINGLE, size: 1, color: C.grayBorder };
const borders = { top: border, bottom: border, left: border, right: border };
const noBorder = { style: BorderStyle.NONE, size: 0 };
const noBorders = { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder };

const PAGE_W = 12240;
const MARGIN = 1440;
const CONTENT_W = PAGE_W - 2 * MARGIN; // 9360

// ─── Helper functions ───
function heading1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 400, after: 200 },
    children: [new TextRun({ text, bold: true, size: 36, font: "Segoe UI", color: C.primary })],
  });
}

function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 300, after: 150 },
    children: [new TextRun({ text, bold: true, size: 28, font: "Segoe UI", color: C.accent })],
  });
}

function heading3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 200, after: 100 },
    children: [new TextRun({ text, bold: true, size: 24, font: "Segoe UI", color: C.primary })],
  });
}

function para(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 120, line: 276 },
    ...opts,
    children: [new TextRun({ text, size: 22, font: "Segoe UI", color: C.black, ...opts.run })],
  });
}

function paraRuns(runs, opts = {}) {
  return new Paragraph({
    spacing: { after: 120, line: 276 },
    ...opts,
    children: runs.map(r => new TextRun({ size: 22, font: "Segoe UI", color: C.black, ...r })),
  });
}

function bullet(text, ref = "bullets", level = 0) {
  return new Paragraph({
    numbering: { reference: ref, level },
    spacing: { after: 80, line: 276 },
    children: [new TextRun({ text, size: 22, font: "Segoe UI" })],
  });
}

function bulletBold(label, desc, ref = "bullets", level = 0) {
  return new Paragraph({
    numbering: { reference: ref, level },
    spacing: { after: 80, line: 276 },
    children: [
      new TextRun({ text: label, size: 22, font: "Segoe UI", bold: true }),
      new TextRun({ text: " " + desc, size: 22, font: "Segoe UI" }),
    ],
  });
}

function codeBlock(text) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    indent: { left: 360 },
    children: [new TextRun({ text, size: 20, font: "Cascadia Code", color: C.primary })],
  });
}

function separator() {
  return new Paragraph({
    spacing: { before: 200, after: 200 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: C.accent, space: 8 } },
    children: [],
  });
}

function infoBox(title, lines) {
  const rows = [
    new TableRow({
      children: [new TableCell({
        borders: noBorders,
        shading: { fill: C.accent, type: ShadingType.CLEAR },
        margins: { top: 80, bottom: 80, left: 200, right: 200 },
        width: { size: CONTENT_W, type: WidthType.DXA },
        children: [new Paragraph({ children: [new TextRun({ text: title, size: 22, font: "Segoe UI", bold: true, color: C.white })] })],
      })],
    }),
    ...lines.map(line =>
      new TableRow({
        children: [new TableCell({
          borders: { top: noBorder, bottom: noBorder, left: { style: BorderStyle.SINGLE, size: 6, color: C.accent }, right: noBorder },
          shading: { fill: "EBF5FB", type: ShadingType.CLEAR },
          margins: { top: 60, bottom: 60, left: 200, right: 200 },
          width: { size: CONTENT_W, type: WidthType.DXA },
          children: [new Paragraph({ children: [new TextRun({ text: line, size: 20, font: "Segoe UI", color: C.primary })] })],
        })],
      })
    ),
  ];
  return new Table({ width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: [CONTENT_W], rows });
}

function tableHeader(cells, widths) {
  return new TableRow({
    tableHeader: true,
    children: cells.map((text, i) => new TableCell({
      borders,
      shading: { fill: C.primary, type: ShadingType.CLEAR },
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      width: { size: widths[i], type: WidthType.DXA },
      children: [new Paragraph({ children: [new TextRun({ text, size: 20, font: "Segoe UI", bold: true, color: C.white })] })],
    })),
  });
}

function tableRow(cells, widths, shade = false) {
  return new TableRow({
    children: cells.map((text, i) => new TableCell({
      borders,
      shading: shade ? { fill: C.bg, type: ShadingType.CLEAR } : undefined,
      margins: { top: 60, bottom: 60, left: 120, right: 120 },
      width: { size: widths[i], type: WidthType.DXA },
      children: [new Paragraph({ children: [new TextRun({ text, size: 20, font: "Segoe UI" })] })],
    })),
  });
}

function dataTable(headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      tableHeader(headers, widths),
      ...rows.map((r, i) => tableRow(r, widths, i % 2 === 1)),
    ],
  });
}

// ─── Build Document ───
const doc = new Document({
  styles: {
    default: {
      document: { run: { font: "Segoe UI", size: 22 } },
    },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 36, bold: true, font: "Segoe UI", color: C.primary },
        paragraph: { spacing: { before: 400, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Segoe UI", color: C.accent },
        paragraph: { spacing: { before: 300, after: 150 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Segoe UI", color: C.primary },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      {
        reference: "bullets",
        levels: [{
          level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }, {
          level: 1, format: LevelFormat.BULLET, text: "\u25E6", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 1080, hanging: 360 } } },
        }],
      },
      {
        reference: "numbers",
        levels: [{
          level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
      {
        reference: "numbers2",
        levels: [{
          level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
      {
        reference: "numbers3",
        levels: [{
          level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
    ],
  },
  sections: [
    // ═══════════════════════════════════════════════
    // COVER PAGE
    // ═══════════════════════════════════════════════
    {
      properties: {
        page: {
          size: { width: PAGE_W, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      children: [
        new Paragraph({ spacing: { before: 2400 }, children: [] }),

        // Title block
        new Table({
          width: { size: CONTENT_W, type: WidthType.DXA },
          columnWidths: [CONTENT_W],
          rows: [
            new TableRow({
              children: [new TableCell({
                borders: noBorders,
                shading: { fill: C.primary, type: ShadingType.CLEAR },
                margins: { top: 400, bottom: 400, left: 400, right: 400 },
                width: { size: CONTENT_W, type: WidthType.DXA },
                children: [
                  new Paragraph({
                    alignment: AlignmentType.CENTER,
                    spacing: { after: 200 },
                    children: [new TextRun({ text: "CORVUS", size: 72, bold: true, font: "Segoe UI", color: C.white })],
                  }),
                  new Paragraph({
                    alignment: AlignmentType.CENTER,
                    spacing: { after: 100 },
                    children: [new TextRun({ text: "ENDPOINT THREAT DETECTION SCANNER", size: 28, font: "Segoe UI", color: "87CEEB" })],
                  }),
                  new Paragraph({
                    alignment: AlignmentType.CENTER,
                    children: [new TextRun({ text: "Teknik Dokümantasyon ve Kullanım Kılavuzu", size: 24, font: "Segoe UI", color: C.grayLight, italics: true })],
                  }),
                ],
              })],
            }),
          ],
        }),

        new Paragraph({ spacing: { before: 600 }, children: [] }),

        // Meta info
        new Table({
          width: { size: 5400, type: WidthType.DXA },
          columnWidths: [2200, 3200],
          rows: [
            ["Sürüm", "2.0"],
            ["Tarih", "Mart 2026"],
            ["Platform", "Windows 10/11 (x64)"],
            ["Lisans", "Özel Kullanım"],
            ["Yazar", "Burak Akgül"],
          ].map(([k, v], i) => new TableRow({
            children: [
              new TableCell({
                borders: noBorders,
                width: { size: 2200, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 120, right: 80 },
                children: [new Paragraph({ children: [new TextRun({ text: k, size: 22, font: "Segoe UI", bold: true, color: C.gray })] })],
              }),
              new TableCell({
                borders: noBorders,
                width: { size: 3200, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 80, right: 120 },
                children: [new Paragraph({ children: [new TextRun({ text: v, size: 22, font: "Segoe UI", color: C.black })] })],
              }),
            ],
          })),
        }),

        new Paragraph({ spacing: { before: 1200 }, children: [] }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          border: { top: { style: BorderStyle.SINGLE, size: 2, color: C.accent, space: 8 } },
          spacing: { before: 200 },
          children: [new TextRun({ text: "GİZLİ — Yetkisiz dağıtımı yasaktır", size: 18, font: "Segoe UI", color: C.accent2, italics: true })],
        }),
      ],
    },

    // ═══════════════════════════════════════════════
    // TABLE OF CONTENTS
    // ═══════════════════════════════════════════════
    {
      properties: {
        page: {
          size: { width: PAGE_W, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: C.accent, space: 4 } },
            children: [
              new TextRun({ text: "Corvus Endpoint Scanner — Teknik Dokümantasyon", size: 18, font: "Segoe UI", color: C.gray, italics: true }),
            ],
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: "Sayfa ", size: 18, font: "Segoe UI", color: C.gray }),
              new TextRun({ children: [PageNumber.CURRENT], size: 18, font: "Segoe UI", color: C.gray }),
            ],
          })],
        }),
      },
      children: [
        new Paragraph({
          spacing: { after: 400 },
          children: [new TextRun({ text: "İÇİNDEKİLER", size: 36, bold: true, font: "Segoe UI", color: C.primary })],
        }),

        ...[
          ["1.", "Genel Bakış"],
          ["2.", "Mimari ve Tasarım Felsefesi"],
          ["3.", "Kurulum ve Derleme"],
          ["4.", "Çalıştırma Rehberi"],
          ["5.", "Tarayıcı Modülleri (22 Modül)"],
          ["6.", "Konfigürasyon (config.json)"],
          ["7.", "Risk Skorlama Sistemi"],
          ["8.", "IOC Veritabanı ve Güncelleme"],
          ["9.", "Raporlama Sistemi"],
          ["10.", "MITRE ATT&CK Eşleştirmesi"],
          ["11.", "Tarama Karşılaştırma (Diff)"],
          ["12.", "Güvenlik İlkeleri"],
          ["13.", "Sorun Giderme"],
          ["14.", "Proje Yapısı"],
        ].map(([num, title]) => new Paragraph({
          spacing: { after: 160 },
          indent: { left: 360 },
          children: [
            new TextRun({ text: num + " ", size: 24, font: "Segoe UI", bold: true, color: C.accent }),
            new TextRun({ text: title, size: 24, font: "Segoe UI", color: C.primary }),
          ],
        })),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 1. GENEL BAKIŞ
        // ═══════════════════════════════════════════════
        heading1("1. Genel Bakış"),
        para("Corvus, Windows uç noktalarında (endpoint) güvenlik tehditleri tespit etmek için geliştirilmiş taşınabilir, çevrimdışı (offline) bir güvenlik tarama aracıdır. Tek bir EXE dosyası olarak çalışır, hedef sisteme kurulum gerektirmez ve sistemi hiçbir şekilde değiştirmez."),

        heading2("1.1 Corvus Nedir?"),
        para("Corvus bir EDR (Endpoint Detection and Response) veya sürekli izleme aracı değildir. Felsefesi şudur:"),

        infoBox("Çalışma Felsefesi", [
          "Bırak → Tara → Raporla → Ayrıl (Drop → Scan → Report → Leave)",
          "Agentless: Hedef sisteme hiçbir şey kurulmaz",
          "Offline: İnternet bağlantısı gerektirmez (isteğe bağlı IOC güncelleme hariç)",
          "Read-Only: Sistemi ASLA değiştirmez (registry, dosya, servis)",
          "Single-EXE: Tek dosya, sıfır bağımlılık",
        ]),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("1.2 Ne Yapar?"),
        para("Corvus, 22 farklı tarayıcı modülü ile uç noktada aşağıdaki kontrolleri gerçekleştirir:"),
        bullet("Çalışan süreçlerin analizi (typosquatting, LOLBin kötüye kullanımı, parent-child anomalileri)"),
        bullet("Dosya sistemi taraması (YARA kuralları, hash IOC eşleştirme, PE entropy analizi)"),
        bullet("Ağ bağlantıları kontrolü (kötü amaçlı IP/domain tespiti)"),
        bullet("Kalıcılık mekanizmaları tespiti (Registry Run key, Scheduled Task, WMI)"),
        bullet("Bellek enjeksiyon tespiti (RWX bellek bölgeleri)"),
        bullet("Güvenlik yapılandırması denetimi (Firewall, UAC, BitLocker, LSASS koruma)"),
        bullet("Sertifika deposu kontrolü (sahte root CA, süresi dolmuş sertifika)"),
        bullet("Tarayıcı uzantıları, PowerShell geçmişi, kimlik bilgisi ifşası ve daha fazlası"),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 2. MİMARİ
        // ═══════════════════════════════════════════════
        heading1("2. Mimari ve Tasarım Felsefesi"),

        heading2("2.1 Genel Mimari"),
        para("Corvus modüler bir mimari kullanır. Ana bileşenler:"),

        dataTable(
          ["Bileşen", "Dosya", "Görev"],
          [
            ["Orkestratör", "src/main.py", "CLI ayrıştırma, modül yönetimi, rapor tetikleme"],
            ["Scanner Core", "src/scanner_core/", "Veri modelleri, konfigürasyon, logging, yardımcı fonksiyonlar"],
            ["Tarayıcı Modülleri", "src/scanners/", "22 bağımsız tarayıcı modülü"],
            ["Raporlama", "src/report/", "HTML ve JSON rapor oluşturma"],
            ["IOC Güncelleyici", "src/ioc_updater.py", "abuse.ch beslemelerinden IOC güncelleme"],
          ],
          [2000, 2600, 4760],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("2.2 Çalışma Akışı"),
        para("Corvus başlatıldığında aşağıdaki sırada işlem yapar:"),

        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "Konsol encoding düzeltme (UTF-8) ve ANSI renk desteği etkinleştirme", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "CLI argümanlarını ayrıştırma (argparse)", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "ASCII karga animasyonu ve CORVUS banner gösterimi", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "config.json yükleme ve doğrulama", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "Pre-flight kontrolleri (admin, OS, disk, process priority)", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "Modülleri sıralı çalıştırma (paralel KULLANILMAZ, sistem güvenliği için)", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "Bulguları toplama ve risk skoru hesaplama", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "HTML + JSON rapor üretme", size: 22, font: "Segoe UI" })],
        }),
        new Paragraph({
          numbering: { reference: "numbers", level: 0 },
          spacing: { after: 80 },
          children: [new TextRun({ text: "Raporu otomatik olarak tarayıcıda açma", size: 22, font: "Segoe UI" })],
        }),

        heading2("2.3 Neden Paralel Çalışmıyor?"),
        para("Modüller sıralı (sequential) çalışır. Bunun nedeni hedef endpoint üzerinde paylaşılan sistem kaynaklarına (registry, WMI, psutil) eş zamanlı erişimin race condition ve hatalı sonuçlara yol açmasıdır. IOThrottle mekanizması disk I/O baskısını kontrol eder."),

        heading2("2.4 Derleme Teknolojisi"),
        para("Corvus, Nuitka derleyicisi ile Python kodunu C kaynak koduna, ardından Zig derleyicisi ile native binary'ye dönüştürür. Bu yaklaşım PyInstaller'a göre önemli avantajlar sağlar:"),
        bullet("AV false positive oranı çok daha düşük (PyInstaller bootloader sık sık flaglenir)"),
        bullet("Daha hızlı başlatma süresi (native kod, interpreter bootstrap yok)"),
        bullet("Tek dosya (onefile) çıktı, runtime extraction ile çalışır"),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 3. KURULUM ve DERLEME
        // ═══════════════════════════════════════════════
        heading1("3. Kurulum ve Derleme"),

        heading2("3.1 Gereksinimler"),
        dataTable(
          ["Gereksinim", "Minimum Sürüm", "Açıklama"],
          [
            ["Python", "3.10+", "Ana geliştirme dili"],
            ["Nuitka", "2.x+", "Python → C → Native derleyici"],
            ["C Derleyici", "MSVC veya MinGW", "Nuitka için gerekli (Zig otomatik indirilir)"],
            ["psutil", "5.9+", "Süreç ve ağ bilgileri"],
            ["yara-python", "4.3+", "YARA kural motoru"],
            ["tqdm", "4.x+", "İlerleme çubuğu (isteğe bağlı)"],
          ],
          [2400, 2000, 4960],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("3.2 Bağımlılıkların Kurulumu"),
        codeBlock("pip install -r requirements.txt"),
        para("Geliştirme ortamı için (test araçları dahil):"),
        codeBlock("pip install -r requirements-dev.txt"),

        heading2("3.3 Derleme (build.bat)"),
        para("Proje kökündeki build.bat dosyasını çalıştırarak EXE oluşturulur:"),
        codeBlock("build.bat"),

        infoBox("Derleme Notları", [
          "İlk derleme 5-10 dakika sürer, sonraki derlemeler cache sayesinde daha hızlıdır",
          "Nuitka, Zig derleyicisini otomatik olarak indirir (Python 3.13+ için)",
          "Çıktı: corvus.exe (proje kök dizininde)",
          "config.json, iocs/ ve yara_rules/ dizinleri EXE içine gömülür",
        ]),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("3.4 Windows Defender Exclusion"),
        para("Nuitka ile derlenen binary'ler Windows Defender tarafından hatalı olarak işaretlenebilir. Aşağıdaki PowerShell komutlarını Administrator olarak çalıştırın:"),

        codeBlock('Add-MpPreference -ExclusionPath "C:\\Users\\<user>\\Desktop\\corvus\\corvus.exe"'),
        codeBlock('Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\\corvus_runtime"'),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 4. ÇALIŞTIRMA
        // ═══════════════════════════════════════════════
        heading1("4. Çalıştırma Rehberi"),

        heading2("4.1 Temel Kullanım"),
        dataTable(
          ["Komut", "Açıklama"],
          [
            ["corvus.exe", "Tam tarama (full profil), rapor Desktop'a kaydedilir"],
            ["corvus.exe --quick", "Hızlı tarama (~30sn), ağır modüller atlanır"],
            ["corvus.exe --profile forensic", "Derin adli analiz taraması (~15dk)"],
            ["corvus.exe -m file,network,process", "Sadece belirtilen modülleri çalıştır"],
            ["corvus.exe -o C:\\Reports", "Raporları özel dizine kaydet"],
            ["corvus.exe --no-open", "Raporu otomatik açma"],
            ["corvus.exe --diff onceki_rapor.json", "Önceki taramayla karşılaştır"],
            ["corvus.exe --update-iocs", "IOC veritabanını güncelle (internet gerekli)"],
            ["corvus.exe --ioc-info", "IOC veritabanı durumunu göster"],
            ["corvus.exe --list-modules", "Tüm modülleri listele"],
            ["corvus.exe --list-profiles", "Tarama profillerini listele"],
          ],
          [5000, 4360],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("4.2 Tarama Profilleri"),
        para("Corvus dört tarama profili sunar, her biri farklı derinlik ve hız dengesi sağlar:"),

        dataTable(
          ["Profil", "Süre", "Modül", "Kullanım Senaryosu"],
          [
            ["quick", "~30sn", "19/22", "Hızlı triage, olay müdahale başlangıcı"],
            ["standard", "~3dk", "21/22", "Günlük güvenlik kontrolü"],
            ["full", "~12dk", "22/22", "Kapsamlı tarama (varsayılan)"],
            ["forensic", "~15dk", "22/22", "Derin adli analiz, maksimum derinlik"],
          ],
          [1800, 1200, 1600, 4760],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        infoBox("Önemli Not: Administrator Yetkisi", [
          "Corvus, Administrator yetkisi OLMADAN da çalışır ancak görünürlük sınırlı olur.",
          "Administrator olmadan eksik kalanlar: Prefetch, BAM/DAM, tam Event Log, ADS derin tarama",
          "En iyi sonuç için: Sağ tık → Yönetici olarak çalıştır",
        ]),

        heading2("4.3 Rapor Çıktısı"),
        para("Her tarama sonucunda aşağıdaki dosyalar üretilir:"),
        bulletBold("HTML Rapor:", "Karanlık temalı, bağımsız (standalone) HTML dosyası. Tarayıcıda açılır."),
        bulletBold("JSON Rapor:", "Makine tarafından okunabilir yapılandırılmış veri. SIEM entegrasyonu için uygundur."),
        bulletBold("Log Dosyası:", "Tarama sırasında oluşan tüm olayların detaylı kaydı."),
        para("Varsayılan kayıt dizini: Desktop\\SecurityScanReports\\"),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 5. TARAYICI MODÜLLERİ
        // ═══════════════════════════════════════════════
        heading1("5. Tarayıcı Modülleri"),
        para("Corvus, 22 bağımsız tarayıcı modülü içerir. Her modül scan() fonksiyonu ile List[Finding] döndürür."),

        dataTable(
          ["#", "Modül", "Açıklama", "MITRE"],
          [
            ["1", "File Scanner", "YARA kuralları, hash IOC eşleştirme, PE entropy, packer tespiti", "T1027.002"],
            ["2", "Network Scanner", "Aktif TCP bağlantıları, kötü amaçlı IP eşleştirme", "T1071"],
            ["3", "Persistence Scanner", "Registry Run key, Scheduled Task, WMI abonelikleri", "T1547.001"],
            ["4", "Process Scanner", "Typosquatting, LOLBin kötüye kullanımı, parent-child analizi", "T1059"],
            ["5", "Memory Scanner", "RWX bellek bölgeleri, süreç enjeksiyonu tespiti", "T1055"],
            ["6", "Vulnerability Scanner", "Çevrimdışı CVE eşleştirme", "—"],
            ["7", "Service Scanner", "Şüpheli Windows servisleri", "T1543.003"],
            ["8", "Event Log Scanner", "Başarısız girişler, yetki yükseltme olayları", "T1078"],
            ["9", "Security Config", "Firewall, UAC, BitLocker, LSASS durumu", "T1562"],
            ["10", "DNS Scanner", "DNS önbellek analizi, DGA tespiti", "T1071.004"],
            ["11", "Port Scanner", "Açık port numaralandırma", "T1046"],
            ["12", "Hosts Scanner", "Hosts dosyası manipülasyonu tespiti", "T1565.001"],
            ["13", "ADS Scanner", "NTFS Alternate Data Streams tespiti", "T1564.004"],
            ["14", "Pipe Scanner", "Named pipe C2 kalıpları", "T1570"],
            ["15", "DLL Hijack", "DLL arama sırası manipülasyonu", "T1574.001"],
            ["16", "Amcache Scanner", "Amcache, UserAssist, BAM/DAM analizi", "T1036"],
            ["17", "Prefetch Scanner", "Prefetch çalıştırma geçmişi", "—"],
            ["18", "PS History", "PowerShell komut geçmişi analizi", "T1059.001"],
            ["19", "Credential Scanner", "Açık kimlik bilgisi tespiti (registry)", "T1552"],
            ["20", "Browser Scanner", "Kötü amaçlı tarayıcı uzantıları", "T1176"],
            ["21", "Attack Vector", ".lnk/.iso/.chm/.xll/.vhd tehlikeli uzantı tespiti", "T1204.002"],
            ["22", "Certificate Store", "Sahte root CA, süresi dolmuş, zayıf algoritma", "T1553.004"],
          ],
          [400, 2000, 5200, 1760],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("5.1 Ağır (Heavy) Modüller"),
        para("Aşağıdaki modüller yoğun disk I/O gerçekleştirir ve --quick modunda atlanır:"),
        bulletBold("file_scanner:", "Tüm disk üzerinde YARA taraması ve hash kontrolü"),
        bulletBold("memory_scanner:", "Her sürecin bellek bölgelerini kontrol eder"),
        bulletBold("ads_scanner:", "NTFS Alternate Data Stream taraması"),

        heading2("5.2 Modül Kontratı"),
        para("Her tarayıcı modülü aşağıdaki yapıyı takip etmelidir:"),
        codeBlock("from scanner_core.utils import Finding, RiskLevel, print_section, print_finding"),
        codeBlock("def scan() -> List[Finding]:"),
        codeBlock("    findings = []"),
        codeBlock("    # detection logic"),
        codeBlock("    return findings"),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 6. KONFİGÜRASYON
        // ═══════════════════════════════════════════════
        heading1("6. Konfigürasyon (config.json)"),
        para("config.json dosyası tarayıcının davranışını kontrol eder. Dosya silinse bile varsayılan değerlerle çalışır."),

        heading2("6.1 Tarama Ayarları (scan)"),
        dataTable(
          ["Parametre", "Varsayılan", "Aralık", "Açıklama"],
          [
            ["max_file_size_mb", "50", "1-500", "Taranacak maksimum dosya boyutu (MB)"],
            ["max_signature_scan_size_mb", "10", "1-100", "İmza taraması boyut sınırı"],
            ["file_scan_threads", "4", "1-16", "Dosya tarama thread sayısı"],
            ["file_scan_max_depth", "10", "1-50", "Dizin derinliği sınırı"],
            ["memory_scan_max_per_process_mb", "50", "1-500", "Süreç başına bellek tarama sınırı"],
            ["event_log_days", "7", "1-365", "Olay günlüğü geriye bakış süresi (gün)"],
            ["event_log_max_events", "2000", "100-50000", "İşlenecek maksimum olay sayısı"],
          ],
          [3200, 1400, 1200, 3560],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("6.2 Modül Açma/Kapama (modules)"),
        para("Her modül true/false ile açılıp kapatılabilir. Örneğin dosya taramasını devre dışı bırakmak için:"),
        codeBlock('"file_scanner": false'),

        heading2("6.3 İstisnalar (exclusions)"),
        para("Belirli yolları, süreçleri veya hash değerlerini taramadan hariç tutabilirsiniz:"),
        codeBlock('"exclusions": {'),
        codeBlock('  "paths": ["C:\\\\Tools\\\\DevKit"],'),
        codeBlock('  "processes": ["myapp.exe"],'),
        codeBlock('  "hashes": ["abc123..."]'),
        codeBlock('}'),

        heading2("6.4 Çıktı Ayarları (output)"),
        bulletBold("html_report:", "HTML rapor üret (true/false)"),
        bulletBold("json_report:", "JSON rapor üret (true/false)"),
        bulletBold("log_level:", "Log seviyesi (DEBUG, INFO, WARNING, ERROR, CRITICAL)"),
        bulletBold("auto_open_report:", "Tarama sonrası raporu otomatik aç (true/false)"),

        heading2("6.5 Doğrulama"),
        para("config.json yüklendikten sonra tüm değerler otomatik doğrulanır. Geçersiz değerler varsayılana döner ve uyarı gösterilir. Uygulama asla çökmez."),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 7. RİSK SKORLAMA
        // ═══════════════════════════════════════════════
        heading1("7. Risk Skorlama Sistemi"),
        para("Corvus, toplanan tüm bulguların ağırlıklı toplamıyla 0-100 arası bir güvenlik skoru hesaplar. Hesaplama tek bir kaynaktan yapılır: src/scanner_core/models.py"),

        heading2("7.1 Skor Hesaplama"),
        para("Başlangıç skoru 100'dür. Her bulgu risk seviyesine göre puan düşürür:"),

        dataTable(
          ["Risk Seviyesi", "Düşüş", "Renk Kodu", "Anlamı"],
          [
            ["CRITICAL", "-15", "#ff4757", "Aktif tehdit veya ciddi güvenlik ihlali"],
            ["HIGH", "-8", "#ff6b35", "Yüksek riskli yapılandırma hatası veya şüpheli aktivite"],
            ["MEDIUM", "-3", "#ffa502", "Orta seviye risk, dikkat gerektirir"],
            ["INFO", "-1", "#3498db", "Bilgilendirme, düşük risk"],
          ],
          [2200, 1200, 1800, 4160],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        para("Formül: Score = max(0, min(100, 100 - toplam_düşüş))"),

        heading2("7.2 Skor Yorumlama"),
        dataTable(
          ["Skor Aralığı", "Değerlendirme", "Aksiyon"],
          [
            ["90-100", "Mükemmel", "Sistem temiz görünüyor"],
            ["70-89", "İyi", "Küçük iyileştirmeler gerekebilir"],
            ["50-69", "Orta", "İnceleme gerekli"],
            ["30-49", "Kötü", "Acil müdahale önerilir"],
            ["0-29", "Kritik", "Olası aktif tehdit, derhal müdahale"],
          ],
          [2200, 2200, 4960],
        ),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 8. IOC VERİTABANI
        // ═══════════════════════════════════════════════
        heading1("8. IOC Veritabanı ve Güncelleme"),
        para("Corvus, bilinen kötü amaçlı göstergeleri (Indicator of Compromise) yerel dosyalarda tutar."),

        heading2("8.1 IOC Dosyaları"),
        dataTable(
          ["Dosya", "Tür", "Kaynak"],
          [
            ["iocs/bad_ips.txt", "Kötü amaçlı IP adresleri", "Feodo Tracker (abuse.ch)"],
            ["iocs/bad_domains.txt", "Kötü amaçlı alan adları", "URLhaus (abuse.ch)"],
            ["iocs/bad_hashes.txt", "Kötü amaçlı dosya hash'leri (SHA256)", "MalwareBazaar (abuse.ch)"],
            ["iocs/cve_database.json", "CVE veritabanı", "Manuel"],
            ["iocs/malware_signatures.json", "Zararlı yazılım imzaları", "Manuel"],
          ],
          [3200, 3200, 2960],
        ),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("8.2 Otomatik Güncelleme"),
        para("--update-iocs bayrağı ile abuse.ch beslemelerinden güncel IOC verileri çekilir ve mevcut verilerle birleştirilir:"),
        codeBlock("corvus.exe --update-iocs"),
        bullet("Mevcut manuel girişler ASLA silinmez (birleşim/union stratejisi)"),
        bullet("Her güncelleme sonrası metadata başlığı yazılır (zaman damgası, kaynak, sayı)"),
        bullet("İnternet bağlantısı yalnızca bu komut için gereklidir"),
        bullet("SSL bağlantısı ve 30 saniye zaman aşımı"),

        heading2("8.3 IOC Durum Kontrolü"),
        codeBlock("corvus.exe --ioc-info"),
        para("Bu komut her IOC dosyasının son güncelleme zamanını, kaynak bilgisini ve giriş sayısını gösterir."),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 9. RAPORLAMA
        // ═══════════════════════════════════════════════
        heading1("9. Raporlama Sistemi"),

        heading2("9.1 HTML Rapor"),
        para("Karanlık temalı, bağımsız (standalone) HTML raporu aşağıdaki bölümleri içerir:"),
        bullet("Yönetici Özeti (Executive Summary): Genel skor, bulgu sayıları, süre"),
        bullet("Risk Skoru gösterimi (renk kodlu)"),
        bullet("MITRE ATT&CK teknik eşleştirmesi"),
        bullet("Modül bazlı bulgu listesi (CRITICAL > HIGH > MEDIUM > INFO sıralı)"),
        bullet("Sistem bilgileri (hostname, OS, kullanıcı, tarama zamanı)"),
        bullet("Modül performans süreleri"),
        bullet("Baseline karşılaştırma kartı (--diff kullanıldığında)"),

        heading2("9.2 JSON Rapor"),
        para("Makine tarafından okunabilir JSON rapor aşağıdaki yapıdadır:"),
        bullet("scanner: Uygulama adı"),
        bullet("scan_time: ISO 8601 zaman damgası"),
        bullet("hostname, username, os, admin: Sistem meta verisi"),
        bullet("risk_score: 0-100 güvenlik skoru"),
        bullet("summary: Seviye bazlı bulgu sayıları"),
        bullet("mitre_techniques: En sık karşılaşılan ATT&CK teknikleri"),
        bullet("module_timings: Modül bazlı çalışma süreleri"),
        bullet("findings: Tüm bulguların detaylı listesi"),
        bullet("diff: Baseline karşılaştırma verisi (--diff ile)"),

        heading2("9.3 Log Dosyası"),
        para("Her tarama bir log dosyası üretir (scan_log_YYYYMMDD_HHMMSS.txt). Konsol çıktısı ve dosya logu eş zamanlı çalışır. Dosya logu DEBUG seviyesinden başlar ve zaman damgalıdır."),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 10. MITRE ATT&CK
        // ═══════════════════════════════════════════════
        heading1("10. MITRE ATT&CK Eşleştirmesi"),
        para("Her bulgu, ilgili MITRE ATT&CK teknik ID'si ile etiketlenir. Alt teknikler (sub-technique) tercih edilir:"),

        dataTable(
          ["Teknik ID", "Teknik Adı", "İlgili Modül"],
          [
            ["T1059.001", "PowerShell", "Process, PS History"],
            ["T1059.003", "Windows Command Shell", "Process Scanner"],
            ["T1218.005", "Mshta", "Process Scanner"],
            ["T1218.010", "Regsvr32", "Process Scanner"],
            ["T1218.011", "Rundll32", "Process Scanner"],
            ["T1547.001", "Registry Run Keys", "Persistence"],
            ["T1055", "Process Injection", "Memory Scanner"],
            ["T1027.002", "Software Packing", "File Scanner"],
            ["T1204.002", "Malicious File", "Attack Vector"],
            ["T1553.004", "Install Root Certificate", "Certificate Store"],
            ["T1553.005", "Mark-of-the-Web Bypass", "Attack Vector"],
            ["T1552.001", "Credentials In Files", "Credential Scanner"],
            ["T1552.002", "Credentials in Registry", "Credential Scanner"],
            ["T1574.001", "DLL Search Order Hijacking", "DLL Hijack"],
            ["T1176", "Browser Extensions", "Browser Scanner"],
            ["T1197", "BITS Jobs", "Process Scanner"],
          ],
          [1800, 3800, 3760],
        ),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 11. DIFF
        // ═══════════════════════════════════════════════
        heading1("11. Tarama Karşılaştırma (Diff)"),
        para("--diff bayrağı ile önceki bir JSON rapor ile mevcut taramayı karşılaştırabilirsiniz:"),
        codeBlock("corvus.exe --diff onceki_rapor.json"),

        heading2("11.1 Karşılaştırma Mantığı"),
        para("Kimlik anahtarı olarak (module, title) çifti kullanılır. Sonuçlar üç kategoride raporlanır:"),
        bulletBold("NEW:", "Önceki taramada olmayan, yeni tespit edilen bulgular"),
        bulletBold("RESOLVED:", "Önceki taramada olup artık mevcut olmayan bulgular"),
        bulletBold("UNCHANGED:", "Her iki taramada da mevcut olan bulgular"),
        para("Skor değişimi ok işaretleri ile gösterilir (↑ artış, ↓ azalış, = değişmedi)."),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 12. GÜVENLİK İLKELERİ
        // ═══════════════════════════════════════════════
        heading1("12. Güvenlik İlkeleri"),

        infoBox("Kırmızı Çizgiler — İhlal Edilemez", [
          "READ-ONLY: Registry, servis, dosya ASLA değiştirilmez",
          "OFFLINE: Tam çevrimdışı çalışma (--update-iocs hariç)",
          "subprocess: Her zaman timeout ve shell=False kullanılır",
          "Dosya okuma: Her zaman try/except PermissionError ile korunur",
          "ctypes: Tüm handle'lar doğrulanır, return değerleri kontrol edilir",
        ]),

        new Paragraph({ spacing: { before: 200 }, children: [] }),

        heading2("12.1 False Positive Yönetimi"),
        para("Corvus, yanlış pozitif oranını minimize etmek için çok katmanlı bir kontrol zinciri uygular:"),
        new Paragraph({
          numbering: { reference: "numbers2", level: 0 },
          spacing: { after: 80 },
          children: [
            new TextRun({ text: "check_file_signature()", size: 22, font: "Segoe UI", bold: true }),
            new TextRun({ text: " — Dosyanın dijital imzası kontrol edilir (ctypes WinVerifyTrust)", size: 22, font: "Segoe UI" }),
          ],
        }),
        new Paragraph({
          numbering: { reference: "numbers2", level: 0 },
          spacing: { after: 80 },
          children: [
            new TextRun({ text: "is_trusted_signer()", size: 22, font: "Segoe UI", bold: true }),
            new TextRun({ text: " — İmza sahibi güvenilir vendor listesinde mi? (90+ firma)", size: 22, font: "Segoe UI" }),
          ],
        }),
        new Paragraph({
          numbering: { reference: "numbers2", level: 0 },
          spacing: { after: 80 },
          children: [
            new TextRun({ text: "is_known_dev_tool()", size: 22, font: "Segoe UI", bold: true }),
            new TextRun({ text: " — Bilinen geliştirici aracı mı? (VS Code, Node.js, Git vb.)", size: 22, font: "Segoe UI" }),
          ],
        }),
        new Paragraph({
          numbering: { reference: "numbers2", level: 0 },
          spacing: { after: 80 },
          children: [
            new TextRun({ text: "is_os_native_path()", size: 22, font: "Segoe UI", bold: true }),
            new TextRun({ text: " — İşletim sistemi yolunda mı? (C:\\Windows\\, C:\\Program Files\\)", size: 22, font: "Segoe UI" }),
          ],
        }),

        heading2("12.2 İmza Doğrulama"),
        para("İmza kontrolü üç aşamalıdır:"),
        bullet("Embedded Authenticode (ctypes WinVerifyTrust) — ~0.1-1ms"),
        bullet("Catalog-signed dosyalar (CryptCATAdmin API) — ~1-5ms"),
        bullet("PowerShell Get-AuthenticodeSignature fallback — ~200-800ms"),
        para("Sonuçlar LRU cache (maks 2000 giriş) ile saklanır ve tekrar kontrolde cache'den döner."),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 13. SORUN GİDERME
        // ═══════════════════════════════════════════════
        heading1("13. Sorun Giderme"),

        dataTable(
          ["Sorun", "Çözüm"],
          [
            ["Error 225 (DLL virus)", "Windows Defender exclusion ekleyin (Bölüm 3.4)"],
            ["Prefetch verileri okunamıyor", "Administrator olarak çalıştırın"],
            ["Event Log erişim hatası", "Administrator olarak çalıştırın"],
            ["yara-python import hatası", "pip install yara-python (doğru sürüm)"],
            ["Rapor açılmıyor", "--no-open ile çalıştırıp dosyayı manuel açın"],
            ["config.json hatası", "Dosyayı silin; varsayılan değerler kullanılır"],
            ["IOC güncelleme başarısız", "İnternet bağlantısını kontrol edin, SSL/proxy ayarları"],
            ["Çok yüksek false positive", "config.json exclusions bölümüne güvenilen yolları ekleyin"],
            ["Tarama çok yavaş", "--quick veya --profile standard kullanın"],
            ["Bellek yetersiz", "memory_scan_max_per_process_mb değerini düşürün"],
          ],
          [3800, 5560],
        ),

        new Paragraph({ children: [new PageBreak()] }),

        // ═══════════════════════════════════════════════
        // 14. PROJE YAPISI
        // ═══════════════════════════════════════════════
        heading1("14. Proje Yapısı"),
        para("Corvus'un dizin yapısı aşağıdaki gibidir:"),

        codeBlock("corvus/"),
        codeBlock("├── corvus.exe                 → Derlenmiş binary (Nuitka)"),
        codeBlock("├── corvus.ico                 → Uygulama ikonu"),
        codeBlock("├── src/"),
        codeBlock("│   ├── main.py                → Giriş noktası, CLI, orkestratör"),
        codeBlock("│   ├── ioc_updater.py          → IOC güncelleme modülü"),
        codeBlock("│   ├── scanner_core/"),
        codeBlock("│   │   ├── models.py           → Finding, RiskLevel, risk skoru"),
        codeBlock("│   │   ├── utils.py            → Hash, imza, IOC, yardımcılar"),
        codeBlock("│   │   ├── config.py           → Konfigürasyon yükleyici"),
        codeBlock("│   │   └── logger.py           → Konsol + dosya loglama"),
        codeBlock("│   ├── scanners/               → 22 tarayıcı modülü"),
        codeBlock("│   │   ├── __init__.py          → SCANNER_REGISTRY"),
        codeBlock("│   │   ├── file_scanner.py      → YARA + hash + PE analizi"),
        codeBlock("│   │   ├── process_scanner.py   → Süreç + LOLBin analizi"),
        codeBlock("│   │   └── ... (20 modül daha)"),
        codeBlock("│   └── report/"),
        codeBlock("│       ├── html_report.py       → HTML rapor üretici"),
        codeBlock("│       └── json_report.py       → JSON rapor üretici"),
        codeBlock("├── tests/                       → Test dosyaları (pytest)"),
        codeBlock("├── iocs/                        → IOC veritabanları"),
        codeBlock("├── yara_rules/                  → YARA tespit kuralları"),
        codeBlock("├── config.json                  → Çalışma zamanı konfigürasyonu"),
        codeBlock("├── build.bat                    → Derleme betiği (Nuitka + Zig)"),
        codeBlock("├── requirements.txt             → Üretim bağımlılıkları"),
        codeBlock("└── pyproject.toml               → Proje meta verisi"),

        new Paragraph({ spacing: { before: 400 }, children: [] }),
        separator(),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 200 },
          children: [new TextRun({ text: "— Corvus Endpoint Scanner Teknik Dokümantasyonu Sonu —", size: 20, font: "Segoe UI", color: C.gray, italics: true })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 100 },
          children: [new TextRun({ text: "Mart 2026 — v2.0", size: 18, font: "Segoe UI", color: C.grayLight })],
        }),
      ],
    },
  ],
});

// ─── Generate ───
const outputPath = path.join(__dirname, "..", "Corvus_Teknik_Dokumantasyon.docx");
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Document created: ${outputPath}`);
  console.log(`Size: ${(buffer.length / 1024).toFixed(1)} KB`);
});
