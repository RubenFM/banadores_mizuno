#!/usr/bin/env python3
"""
Busca bañadores de competición Mizuno (GX-SONIC) en Mercari Japón
y devuelve enlaces directos a Buyee.

Mercari es accesible desde Europa; Yahoo Auctions NO (bloqueo geo EEA/UK),
por eso Buyee es la unica ventana a Yahoo. Este script cubre Mercari.

Por defecto: talla L, corte hombre, maximo ~200 EUR, solo GX-SONIC 6 y ROYAL
(en cualquier estado); generaciones anteriores solo si estan nuevas (新品、未使用).

Uso:
    python3 buscar.py                          # busqueda por defecto
    python3 buscar.py --max-precio 12000
    python3 buscar.py --talla L --talla XL     # --talla todas = sin filtro
    python3 buscar.py --corte todos --todos-modelos
    python3 buscar.py --query "GXソニック6" --incluir-vendidos
"""
import argparse, base64, json, re, sys, time, uuid, urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

API = "https://api.mercari.jp/v2/entities:search"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# Terminos japoneses que realmente usan los vendedores.
QUERIES_DEFAULT = [
    "GXソニック",            # GX-SONIC en katakana: el termino mas usado
    "GX SONIC 競泳",         # romaji + "competicion"
    "ミズノ 高速水着",        # Mizuno + "banador de alta velocidad" (= tech suit)
    "ミズノ 競泳水着 FINA",   # Mizuno + banador competicion + FINA aprobado
    "GX SONIC ROYAL",
    "GXソニック ロイヤル",
]

EUR_JPY = 175                       # aprox. (175.68 el 2026-10-30)
DEF_TALLAS = ["L"]
DEF_CORTE = "hombre"
DEF_MAX_PRECIO = 200 * EUR_JPY      # 200 EUR
# Modelos que valen en cualquier estado; el resto solo si estan nuevos.
MODELOS_TOP = ("GX-SONIC ROYAL", "GX-SONIC 6")
CONDICION_NUEVO = "1"               # itemConditionId de Mercari: 新品、未使用

# Ruido tipico. OJO: "パナソニック" (Panasonic) contiene "ソニック",
# por eso se descarta explicitamente antes de aplicar SENAL.
RUIDO = re.compile(
    r"VHS|カセット|センサ|シリンダ|ビデオテープ|プラモ|ラジコン"
    r"|パナソニック|Panasonic|LUMIX|カメラ|ストラップ|イヤホン|ヘッドホン", re.I)
# Un resultado valido casi siempre lleva alguno de estos.
# (?<!パナ) evita que "パナソニック" dispare la senal "ソニック".
SENAL = re.compile(r"(?<!パナ)ソニック|SONIC|競泳|水着|ミズノ|MIZUNO|スパッツ", re.I)

# Modelos reales, de mejor a peor. Los ST/MR son los de gama alta.
MODELOS = [
    (re.compile(r"(?:GX[\s・\-]?SONIC|ソニック).*?(?:ROYAL|ロイヤル)", re.I), "GX-SONIC ROYAL"),
    (re.compile(r"GX[\s・\-]?SONIC[\s・\-]?(?:6|VI|Ⅵ)|GXソニック[\s・\-]?6", re.I), "GX-SONIC 6"),
    (re.compile(r"GX[\s・\-]?SONIC[\s・\-]?(?:5|V|Ⅴ)(?![I0-9])|GXソニック[\s・\-]?5", re.I), "GX-SONIC V"),
    (re.compile(r"GX[\s・\-]?SONIC[\s・\-]?(?:4|IV|Ⅳ)|GXソニック[\s・\-]?4", re.I), "GX-SONIC IV"),
    (re.compile(r"GX[\s・\-]?SONIC[\s・\-]?(?:3|III|Ⅲ)|GXソニック[\s・\-]?3", re.I), "GX-SONIC III"),
    (re.compile(r"STREAM|ストリーム", re.I), "GX-SONIC STREAM"),
    (re.compile(r"NEO|ネオ", re.I), "GX-SONIC NEO"),
    (re.compile(r"LITE|ライト", re.I), "GX-SONIC LITE"),
    (re.compile(r"GX[\s・\-]?SONIC|GXソニック", re.I), "GX-SONIC (gen?)"),
]
# Gama dentro de cada generacion: ST > MR > ET; en ROYAL: PW / MT / SF
GAMA = re.compile(r"(?<![A-Z])(ST|MR|ET|PW|MT|SF)(?![A-Z])", re.I)

# Corte / genero. En Japon el corte se nombra explicitamente y delata el genero:
#   hombre -> 競パン (slip), ハーフスパッツ, ショートスパッツ, Vパンツ
#   mujer  -> ハイカット / ミディアムカット / ローカット, ハーフスーツ, オープンバック
CORTE_H = re.compile(r"競パン|ハーフスパッツ|ショートスパッツ|Ｖパンツ|Vパンツ|メンズ|men'?s|男", re.I)
CORTE_M = re.compile(r"ハイカット|ミディアムカット|ローカット|ハーフスーツ|オープンバック"
                     r"|レディース|ladies|women'?s|ウィメンズ|女", re.I)
# Codigo de producto Mizuno (品番): lo mas preciso para buscar el modelo exacto.
CODIGO = re.compile(r"\b(N2[A-Z]{2,3}\d{3,5})\b", re.I)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _dpop(url: str, method: str = "POST") -> str:
    """Mercari exige un JWT DPoP firmado (ES256) por peticion."""
    key = ec.generate_private_key(ec.SECP256R1())
    pn = key.public_key().public_numbers()
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {
        "crv": "P-256", "kty": "EC",
        "x": _b64u(pn.x.to_bytes(32, "big")),
        "y": _b64u(pn.y.to_bytes(32, "big"))}}
    payload = {"iat": int(time.time()), "jti": str(uuid.uuid4()),
               "htu": url, "htm": method, "uuid": str(uuid.uuid4())}
    signing_input = (_b64u(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     _b64u(json.dumps(payload, separators=(",", ":")).encode())).encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return signing_input.decode() + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def buscar(keyword, page_size=120, incluir_vendidos=False, precio_max=0):
    estados = ["STATUS_ON_SALE"]
    if incluir_vendidos:
        estados.append("STATUS_SOLD_OUT")
    body = {
        "userId": "", "pageSize": page_size, "pageToken": "",
        "searchSessionId": str(uuid.uuid4()),
        "indexRouting": "INDEX_ROUTING_UNSPECIFIED", "thumbnailTypes": [],
        "searchCondition": {
            "keyword": keyword, "excludeKeyword": "",
            "sort": "SORT_CREATED_TIME", "order": "ORDER_DESC",
            "status": estados, "sizeId": [], "categoryId": [], "brandId": [],
            "sellerId": [], "priceMin": 0, "priceMax": precio_max,
            "itemConditionId": [], "shippingPayerId": [], "shippingFromArea": [],
            "shippingMethod": [], "colorId": [], "hasCoupon": False,
            "attributes": [], "itemTypes": [], "skuIds": [], "shopIds": []},
        "serviceFrom": "suruga", "withItemBrand": True, "withItemSize": False,
        "withItemPromotions": True, "withItemSizes": True, "withShopname": False,
        "useDynamicAttribute": True, "withSuggestedItems": False,
        "withOfferPricePromotion": False, "withProductSuggest": False,
        "withParentProducts": False, "withProductArticles": False,
        "withSearchConditionId": False}
    req = urllib.request.Request(API, data=json.dumps(body).encode(), headers={
        "Content-Type": "application/json", "DPOP": _dpop(API), "X-Platform": "web",
        "Accept": "*/*", "Accept-Language": "ja,en;q=0.9", "User-Agent": UA,
        "Origin": "https://jp.mercari.com", "Referer": "https://jp.mercari.com/"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r).get("items", [])
    except urllib.error.HTTPError as e:
        print(f"  ! HTTP {e.code} en '{keyword}'", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  ! {type(e).__name__} en '{keyword}': {e}", file=sys.stderr)
        return []


def detectar_talla(nombre):
    """\\b no sirve aqui: en japones no hay espacios y los kana cuentan como \\w,
    asi que "XSサイズ" no daba match. Usamos lookarounds sobre ASCII."""
    m = re.search(r"(?<![A-Za-z0-9])([SML]X0\d|MX0\d)(?![A-Za-z0-9])", nombre)
    if m:
        return m.group(1)
    m = re.search(r"(?<![A-Za-z0-9])(XS|SS|XL|XO|LL|2XL|[SML])(?![A-Za-z0-9])", nombre)
    if m:
        return m.group(1)
    m = re.search(r"(?<!\d)(1[2-7]0)(?!\d)", nombre)   # tallas infantiles japonesas
    return m.group(1) + "cm" if m else "-"


def detectar_corte(nombre):
    h, m = bool(CORTE_H.search(nombre)), bool(CORTE_M.search(nombre))
    if h and not m:
        return "hombre"
    if m and not h:
        return "mujer"
    return "?" if not (h or m) else "mixto"


def detectar_codigo(nombre):
    m = CODIGO.search(nombre)
    return m.group(1).upper() if m else "-"


def detectar_modelo(nombre):
    for rx, etiqueta in MODELOS:
        if rx.search(nombre):
            g = GAMA.search(nombre)
            return f"{etiqueta} {g.group(1).upper()}" if g else etiqueta
    return "-"


def main():
    p = argparse.ArgumentParser(description="Busca Mizuno GX-SONIC en Mercari JP -> Buyee")
    p.add_argument("--query", action="append", help="termino extra (repetible)")
    p.add_argument("--solo-query", action="store_true", help="usar solo --query, sin los por defecto")
    p.add_argument("--max-precio", type=int, default=DEF_MAX_PRECIO,
                   help=f"precio maximo en yenes (0 = sin limite, por defecto {DEF_MAX_PRECIO})")
    p.add_argument("--talla", action="append",
                   help=f"filtrar por talla (repetible, 'todas' = sin filtro, por defecto {DEF_TALLAS})")
    p.add_argument("--incluir-vendidos", action="store_true", help="incluir vendidos (util para ver precios de mercado)")
    p.add_argument("--corte", choices=["hombre", "mujer", "todos"], default=DEF_CORTE,
                   help="filtrar por corte (los ambiguos se conservan)")
    p.add_argument("--todos-modelos", action="store_true",
                   help="cualquier articulo, no solo GX-SONIC 6/ROYAL o anteriores nuevos")
    p.add_argument("--sin-filtro-ruido", action="store_true")
    args = p.parse_args()
    tallas = [] if args.talla and "todas" in args.talla else (args.talla or DEF_TALLAS)

    queries = list(args.query or []) if args.solo_query else QUERIES_DEFAULT + list(args.query or [])
    if not queries:
        p.error("sin terminos de busqueda")

    vistos, resultados = set(), []
    for q in queries:
        print(f"buscando: {q}", file=sys.stderr)
        for it in buscar(q, incluir_vendidos=args.incluir_vendidos, precio_max=args.max_precio):
            iid = it.get("id", "")
            if not iid or iid in vistos:
                continue
            nombre = it.get("name", "")
            if not args.sin_filtro_ruido and (RUIDO.search(nombre) or not SENAL.search(nombre)):
                continue
            talla = detectar_talla(nombre)
            if talla == "-" and it.get("itemSize"):      # talla del formulario de Mercari
                talla = it["itemSize"].get("name") or "-"
            if tallas and talla not in tallas:
                continue
            modelo = detectar_modelo(nombre)
            nuevo = it.get("itemConditionId") == CONDICION_NUEVO
            if not args.todos_modelos:
                if modelo == "-":
                    continue
                if not modelo.startswith(MODELOS_TOP) and not nuevo:
                    continue
            corte = detectar_corte(nombre)
            if args.corte != "todos" and corte not in (args.corte, "?"):
                continue
            vistos.add(iid)
            resultados.append({
                "id": iid, "precio": int(it.get("price") or 0), "nombre": nombre,
                "talla": talla, "modelo": modelo, "corte": corte,
                "codigo": detectar_codigo(nombre), "nuevo": nuevo,
                "vendido": it.get("status") == "ITEM_STATUS_SOLD_OUT",
                "mercari": f"https://jp.mercari.com/item/{iid}",
                "buyee": f"https://buyee.jp/mercari/item/{iid}"})
        time.sleep(1.0)   # cortesia con la API

    resultados.sort(key=lambda r: r["precio"])
    if not resultados:
        print("\nSin resultados. Prueba --sin-filtro-ruido o anade --query.")
        return

    with open("/home/ruben/banadores/resultados.json", "w", encoding="utf-8") as f:
        json.dump(resultados, f, ensure_ascii=False, indent=2)

    print(f"\n{len(resultados)} articulos -> /home/ruben/banadores/resultados.json\n")
    for r in resultados:
        eur = r["precio"] / EUR_JPY      # aprox. JPY -> EUR, solo orientativo
        marca = (" [NUEVO]" if r["nuevo"] else "") + (" [VENDIDO]" if r["vendido"] else "")
        cod = f"  {r['codigo']}" if r['codigo'] != "-" else ""
        print(f"  ¥{r['precio']:>7,}  (~{eur:>5.0f} EUR)  {r['modelo']:<20} "
              f"talla {r['talla']:<6} {r['corte']:<7}{cod}{marca}")
        print(f"    {r['nombre'][:88]}")
        print(f"    Buyee:   {r['buyee']}")
        print(f"    Mercari: {r['mercari']}\n")



if __name__ == "__main__":
    main()
