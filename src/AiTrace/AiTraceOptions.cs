using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AiTrace
{
    public sealed class AiTraceOptions
    {
        /// <summary>
        /// Where audit records are written.
        /// Default: JsonAuditStore in ./aitrace (app base directory).
        /// </summary>
        public IAuditStore Store { get; set; } = new JsonAuditStore();

        /// <summary>
        /// If true, prompts/outputs are stored. If false, only hashes are stored.
        /// Default: true (best for audits; turn off for highly sensitive data).
        /// </summary>
        public bool StoreContent { get; set; } = true;

        /// <summary>
        /// If true, attempts to redact common secrets (API keys, tokens) before storing.
        /// Default: true.
        /// </summary>
        public bool BasicRedaction { get; set; } = true;
    }
}
