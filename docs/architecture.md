# Arquitetura do Reboot

O Reboot usa um único módulo Android `:app`, em Kotlin. A organização por
funcionalidades facilita localizar código e testes no tamanho atual da PoC,
sem separar regras em camadas ou adicionar módulos, DI ou dependências.

## Pacotes

Dentro de `br.com.reboot.poc`:

- `ui`: `MainActivity` e `UiResponseTracker`; interface, consentimento Android
  e acompanhamento das respostas dos comandos.
- `vpn`: `RebootDnsVpnService`, identidade e estado operacional da sessão,
  guarda do ciclo de vida, recursos e resultado de encerramento.
- `dns`: classificação e extração de consultas, encaminhamento upstream,
  construção e inspeção das respostas, sockets e execução de tarefas.
- `protection`: registros de proteção, reconciliação de sessões antigas,
  recuperação de pedidos órfãos e limpeza de encerramentos incompletos.
- `unlock`: prazos, pedidos, coordenação persistente, cancelamento e autorização
  de encerramento voluntário.
- `storage`: implementações com SharedPreferences e codecs dos registros.

Não há pacote `util`: nenhum auxiliar genérico foi necessário.
Os testes seguem esses pacotes em `src/test` (JVM) e `src/androidTest`
(AndroidJUnit4), sem misturar os dois ambientes.

## Interface e serviço

A Activity obtém o consentimento com `VpnService.prepare()` e envia Intents
explícitas para `RebootDnsVpnService`. As actions e extras definidos pelo serviço
continuam sendo o contrato de comunicação. Um `ResultReceiver` recebe o estado,
o identificador do pedido, o tempo restante e mensagens; `UiResponseTracker`
acompanha as respostas. Não existe acesso da interface diretamente ao túnel.

O serviço interage com o Android e coordena início, recursos do túnel, comandos,
revogação e encerramentos técnicos. As classes auxiliares preservam as regras de
sessão, DNS, persistência e autorização fora do serviço.

## Desbloqueio e proteção

`PersistentUnlockCoordinator` persiste pedidos com UUID, sessão, duração,
relógio monotônico e boot associado. As opções continuam sendo 30 minutos,
1 hora, 2 horas e 4 horas. Durante `WAITING`, a VPN permanece ativa. `READY`
apenas permite solicitar confirmação: não encerra automaticamente a VPN.
`UnlockStopAuthorization` e as validações do serviço verificam pedido, prazo
e sessão antes do encerramento explícito. `ACTION_STOP` direto é rejeitado.
Revogação pelo Android e encerramentos técnicos mantêm seus caminhos próprios.

`ProtectionRecoveryCoordinator`, `ProtectionSessionReconciler`,
`OrphanUnlockRecovery` e `PendingStopCleanupRecovery` preservam as verificações
operacionais antes da limpeza. Estado desconhecido não prova inatividade;
registros de outra sessão não devem ser apagados. O marcador de limpeza pendente
é removido por último para permitir nova tentativa após falha.

## Persistência e compatibilidade

Os contratos `ProtectionSessionRecordRepository` e
`PendingStopCleanupRepository` ficam em `protection`;
`PersistentUnlockRepository` fica em `unlock`. São preservados para substituir
armazenamento e simular falhas nos testes, sem um pacote genérico de interfaces.
As implementações concretas ficam em `storage`.

| SharedPreferences | Chave | Formato |
| --- | --- | --- |
| `reboot_protection_session` | `current_protection_session` | `v1`, UUID da sessão, boot e instante de ativação separados por `\|` |
| `reboot_unlock` | `pending_unlock_request` | `v1`, UUID do pedido, UUID da sessão, nome do prazo, instante e boot separados por `\|` |
| `reboot_pending_stop_cleanup` | `pending_stop_session_key` | UUID da sessão |

Não há serialização por nome qualificado de classe. Pacotes, imports e nomes de
componentes no manifesto foram atualizados; nomes das preferências, chaves,
codecs, UUIDs, actions e extras foram preservados. `applicationId` e `namespace`
continuam `br.com.reboot.poc`.

Os nomes dos componentes Android mudaram para `.ui.MainActivity` e
`.vpn.RebootDnsVpnService`. Validar atualização sobre instalação anterior em um
aparelho: dados persistidos são compatíveis, mas atalhos ou referências externas
aos nomes antigos dos componentes podem precisar ser recriados. A continuidade
de uma VPN durante atualização do APK depende do ciclo de vida do Android.

## Validação

Com JDK 17, Android SDK 35 e o SDK configurado em `local.properties`:

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
adb devices -l
./gradlew :app:connectedDebugAndroidTest
```

O último comando requer aparelho autorizado ou emulador disponível. Ele instala
os APKs de aplicativo e testes no dispositivo de desenvolvimento.
Validar manualmente consentimento, DNS real, espera e confirmação de desbloqueio,
cancelamento, revogação pelo Android e recuperação após término de processo ou
reinício. Os testes existentes não substituem esses cenários de integração.

## Cuidados ao evoluir

- Colocar código e testes junto à funcionalidade correspondente.
- Manter o serviço como coordenador e os recursos com fechamento seguro.
- Preservar protocolos DNS, rotas do túnel e proteção dos sockets upstream.
- Não permitir que prazo vencido ou comando direto dispensem autorização.
- Preservar isolamento por UUID, boot e sessão na recuperação e limpeza.
- Tratar falhas de gravação; não trocar `commit()` ou ordem de limpeza sem
  analisar as garantias e os testes de recuperação.
- Alterar formatos persistidos ou contrato de Intents somente com plano explícito
  de compatibilidade e testes. Evitar abstrações que apenas deleguem chamadas.
