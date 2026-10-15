# SPEC — soc-agents

Pipeline **multi-agente** de triagem e investigação de alertas do Wazuh, construído com Google ADK, agentes expostos
como servidores **A2A** e dados obtidos do servidor MCP [`mcp-wazuh`](../../mcp-wazuh) (somente leitura).

> Projeto de portfólio. Prova de **sistemas multi-agente com segurança**: o dado que vem do SIEM é controlado pelo
> atacante, então toda a arquitetura parte da premissa de que qualquer agente pode ser persuadido e limita o dano.

## 1. Objetivo

- Dado um alerta (`--alert-id`) ou a janela mais recente (`--last 1h`), produzir um **relatório de incidente em
  português** com severidade, hipótese, técnicas MITRE, contexto do host, linha do tempo e recomendações.
- Mostrar uma arquitetura multi-agente onde **o fluxo de controle é código, não texto de log**.

## 2. Não-objetivos

- **Nenhuma ação de resposta** (bloquear IP, isolar host, active response). Agentes só recomendam.
- Sem RAG de inteligência de ameaças (existe só um ponto de extensão `ThreatIntelProvider`, sem implementação).
- Sem memória de longo prazo entre investigações; sem UI web.
- Não altera o `mcp-wazuh`.

## 3. Arquitetura

```
CLI (soc-agents investigate)
   │
   ▼
orchestrator  (código determinístico: max_steps, timeout, orçamento, decide parar)
   │  A2A (RemoteA2aAgent, sessão nova por chamada, JSON validado)
   ├──► triage        :9101   tools: search_alerts, get_alert
   ├──► enrichment    :9102   tools: get_agent, get_rule, list_vulnerabilities
   ├──► investigator  :9103   tools: search_alerts, alert_stats
   └──► reporter      :9104   tools: (nenhuma)
              │ MCP stdio
              ▼
          mcp-wazuh  →  Wazuh API / Indexer (contas readonly)
```

Decisões:

1. **Orquestração em código.** O orquestrador não é um LLM; a ordem triage → enrichment → investigator → reporter é fixa
   e os limites são impostos por Python. Um LLM persuadido não consegue pular etapas, repetir em loop ou chamar outro agente.
2. **Um processo A2A por agente**, cada um com Agent Card próprio e porta distinta (`to_a2a` do ADK).
3. **Cada chamada A2A usa uma sessão nova**: não há contexto compartilhado entre agentes além do JSON do contrato.
4. **Modelo** por env (`MODEL`, padrão `gemini-2.5-flash`; prefixo `litellm/` usa `LiteLlm`, ex. `litellm/anthropic/claude-sonnet-4-5`).

## 4. Agentes e permissões

| Agente | Tools MCP permitidas | Entrada | Saída (contrato) |
|---|---|---|---|
| triage | `search_alerts`, `get_alert` | `TriageRequest` | `TriageResult` |
| enrichment | `get_agent`, `get_rule`, `list_vulnerabilities` | `EnrichmentRequest` | `EnrichmentResult` |
| investigator | `search_alerts`, `alert_stats` | `InvestigationRequest` | `InvestigationResult` |
| reporter | nenhuma | `ReportRequest` | markdown (`str`, limite de tamanho) |
| orchestrator | nenhuma (não é LLM) | CLI | `Incident` |

A allowlist é imposta **em código** em duas camadas: `tool_filter` do `McpToolset` (a tool nem é exposta ao modelo) e
`before_tool_callback` (nega e audita qualquer chamada fora da lista, mesmo que o modelo a tente).

## 5. Contratos entre agentes

Modelos pydantic com `extra="forbid"`. Campos de controle são enums, números limitados ou ids por regex. **Texto
livre vindo de log nunca ocupa campo de controle**: ele só aparece em campos `*_text` com tamanho máximo, e esses
campos nunca são usados para decidir fluxo.

- `injection_suspected` é **forçado por código**: um callback marca o estado da sessão quando qualquer tool devolve
  `security.injection_suspected = true`, e o `after_model_callback` faz `OR` com o valor que o modelo escreveu.
  O modelo não consegue limpar a flag.
- Saída fora do schema é rejeitada (`ContractViolation`) e a investigação termina com status `failed`.
- O orquestrador propaga a flag (OR de todas as etapas) para o `Incident`.

## 6. Ameaças principais (detalhe em `docs/threat-model.md`)

| # | Ameaça | Mitigação |
|---|---|---|
| A1 | Prompt injection indireta via log | Dado envelopado pelo mcp-wazuh; instruções dos agentes tratam tool output como dado; flag forçada por código; sem tool de escrita |
| A2 | Agente comprometido tenta usar tool fora do papel | Allowlist por agente em código + teste |
| A3 | Confused deputy (reporter induzido a "agir") | Reporter sem tools; ações só como lista `requires_human_approval` |
| A4 | Envenenamento entre agentes | Contratos pydantic estritos, sessão nova, campos de texto não controlam fluxo |
| A5 | Loop / custo | `max_steps`, timeout, `max_llm_calls`, orçamento de tokens |
| A6 | Vazamento via relatório | Reporter só recebe o JSON do contrato; auditoria; sem segredos no contexto |
| A7 | Relatório oculta a injection | Banner de injection e lista de ações são inseridos **por código**, não pelo reporter |

## 7. Ações sugeridas e aprovação humana

`SuggestedAction { id, kind (enum), target, rationale_text, status = "requires_human_approval" }`. O comando
`soc-agents approve <incident-id> <action-id> --decision approve|reject --by <nome>` **apenas registra** a decisão em
JSONL. Nada é executado.

## 8. Auditoria

JSONL (`AUDIT_LOG_PATH`): um registro por chamada de agente e de tool, com `correlation_id` por investigação,
papel, nome da tool, parâmetros (chaves sensíveis redigidas), resultado (`ok|denied|error`), duração e
`injection_suspected`. Nunca grava segredos nem o conteúdo de logs (apenas ids e tamanhos).

## 9. Limites

`MAX_STEPS` (padrão 6 chamadas de agente), `INVESTIGATION_TIMEOUT_S` (120), `MAX_LLM_CALLS` por agente (8),
`TOKEN_BUDGET` por investigação (60000), `MAX_TOOL_CALLS` por agente (6).

## 10. Testes e critérios de aceite

1. Unitários: contratos, allowlist, redação de auditoria, parsing/forçamento da flag.
2. Adversarial: os alertas com injection do `mcp-wazuh` (sample-alerts) passam pelo pipeline; provar que (a) a flag é
   propagada, (b) a instrução embutida não é obedecida, (c) nenhuma tool fora da allowlist é chamada, (d) não há ação
   de resposta, só `requires_human_approval`.
3. Integração do fluxo completo com um LLM falso determinístico (sem chave de API).
4. E2E opcional (`SOC_E2E=1`) com modelo real contra o lab.
5. Cobertura ≥ 85% no núcleo (`src/soc_agents`, exceto cli/servidor).
6. `ruff`, `mypy` e `pytest` verdes no CI (Python 3.11, 3.12 e 3.13).
7. README em inglês: diagrama, quickstart, exemplo real, tabela agentes × tools × permissões, "Security design",
   "What I learned".
