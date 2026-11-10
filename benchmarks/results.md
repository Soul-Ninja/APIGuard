# APIGuard Benchmark Results
*Measured automatically on 2026-11-10T14:58:26Z against target: `http://127.0.0.1:8000/target`*

## Variant Comparison Table
| Variant | GT | Base Confirmed | Base Recall | Base Prec | Base Req/Fnd | APIGuard Confirmed | APIGuard Recall | APIGuard Prec | APIGuard Req/Fnd | APIGuard Avg ms/Fnd |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `variant_a` | 1 | 1 | 100% | 100% | 7.0 | **1** | **100%** | **100%** | **15.0** | 15.0ms |
| `variant_b` | 1 | 0 | 0% | n/a | - | **1** | **100%** | **100%** | **15.0** | 13.5ms |
| `variant_c` | 1 | 1 | 100% | 100% | 7.0 | **1** | **100%** | **100%** | **15.0** | 10.4ms |
| `variant_all` | 3 | 2 | 67% | 100% | 3.5 | **3** | **100%** | **100%** | **6.3** | 5.4ms |
| `variant_secure` | 0 | 0 | n/a | 100% | - | **0** | **n/a** | **100%** | **-** | - |
| `variant_bfla` | 1 | 0 | 0% | n/a | - | **1** | **100%** | **100%** | **15.0** | 10.0ms |
| `variant_bopla` | 2 | 0 | 0% | n/a | - | **2** | **100%** | **100%** | **8.5** | 5.3ms |
| `variant_auth` | 1 | 0 | 0% | n/a | - | **1** | **100%** | **100%** | **21.0** | 12.9ms |

## Ablations (Measured on Defect B Variant)
| Configuration | Confirmed | Recall | Precision | Requests | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **APIGuard (Propagation ON)** | 1 | 100% | 100% | 15 | Full Graph-Guided Scanner |
| **Ablation: Propagation OFF** | 0 | 0% | n/a | 6 | Propagation off: stops after the main read route |
| **Ablation: Oracle Baseline** | 1 | 100% | 100% | 9 | Baseline with a manual rule for every route |

## Key Takeaways
- **Defect B (Variant `variant_b`):** APIGuard achieves **100% recall** by propagating ownership rules to graph-adjacent operations. Baseline achieves **0% recall** because it only tests routes it was given a rule for, and it has none for `/export`.
- **Zero False Positives:** In `variant_secure`, APIGuard maintains **100% precision** with 0 false positives.
- **Cost:** APIGuard sends more requests than the rules-only baseline because it also tests the nested routes. It finds more; it is not cheaper.
- **Ablation:** See the ablation table above; all values are measured in this run.