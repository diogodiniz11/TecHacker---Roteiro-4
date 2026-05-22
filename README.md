# Roteiro 4

Extensão Firefox para detecção de ameaças à privacidade e rastreamento na navegação web.

## Funcionalidades

- **Terceiros**: lista domínios externos e tipo de recurso (script, imagem, iframe…)
- **Cookies**: diferencia 1ª/3ª parte, sessão/persistentes e supercookies
- **Web Storage**: exibe chaves, tamanhos e domínios (localStorage, sessionStorage)
- **Fingerprinting**: detecta chamadas a Canvas, WebGL e AudioContext
- **Hijacking**: detecta scripts externos suspeitos e redirecionamentos não autorizados
- **Privacy Score**: pontuação 0–100 com metodologia documentada

## Instalação

1. Abra o Firefox e acesse `about:debugging`
2. Clique em **Este Firefox** → **Carregar extensão temporária**
3. Selecione o arquivo `manifest.json` desta pasta

## Uso

Clique no ícone 🔒 na barra do Firefox em qualquer página para ver o relatório.

## Metodologia do Privacy Score

| Critério | Penalidade máxima |
|---|---|
| Domínios de terceira parte (−3 por domínio) | −30 |
| Fingerprinting por categoria detectada (−25 cada) | −75 |
| Cookies de terceira parte (−4 por cookie) | −20 |
| Web Storage com dados (−5) | −5 |
| Scripts suspeitos / hijacking (−10 por ocorrência) | −10 |

- 80–100 -> Privacidade respeitada
- 50–79 -> Privacidade moderada  
- 0–49  -> Alto risco de rastreamento

## Estrutura

```
privacy-monitor/
├── manifest.json
├── content.js        hooks de fingerprinting, storage e hijacking
├── relay.js          bridge content script → background
├── background.js     intercepta rede, cookies e calcula score
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
└── icons/
    └── icon48.png
```
