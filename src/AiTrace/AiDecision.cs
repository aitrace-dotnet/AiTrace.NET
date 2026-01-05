using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AiTrace
{
    public sealed record AiDecision
    {
        public required string Prompt { get; init; }
        public required string Output { get; init; }

        public string? Model { get; init; }
        public string? UserId { get; init; }

        /// <summary>
        /// Optional metadata for audit context (feature name, amounts, correlation ids, etc.).
        /// Keep this small and non-sensitive when possible.
        /// </summary>
        public IDictionary<string, object?> Metadata { get; init; } = new Dictionary<string, object?>();

        /// <summary>
        /// UTC timestamp; will be set automatically if not provided.
        /// </summary>
        public DateTimeOffset? TimestampUtc { get; init; }
    }
}
