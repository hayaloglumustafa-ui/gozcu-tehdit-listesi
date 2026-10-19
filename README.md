# Gözcü tehdit listesi

Gözcü (Android casus yazılım tespit uygulaması) bu depodaki imzalı listeyi her gün indirir.

- `threat_list.signed.json` — uygulamanın indirdiği, ECDSA P-256 ile imzalı liste
- `threat_list.json` — aynı listenin okunabilir hali
- `public_key.pem` — imzayı doğrulayan açık anahtar (uygulamanın içinde de gömülü)
- `tools/build_list.py` — listeyi hazırlayan ve imzalayan araç
- `.github/workflows/guncelle.yml` — her gün otomatik çalışan güncelleme

## Kaynak ve lisans

Göstergeler [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
projesinden alınır ve [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) lisansıyla kullanılır.
Gözcü biçimine dönüştürülmüştür.

Özel imza anahtarı bu depoda **bulunmaz**; yalnızca `GOZCU_SIGNING_KEY` adlı gizli değişkende saklanır.
