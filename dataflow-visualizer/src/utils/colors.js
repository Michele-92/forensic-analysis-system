export const TYPE_CFG = {
  user:     { color: '#60a5fa', rgb: '96,165,250',   label: 'Benutzer',  icon: '👤' },
  frontend: { color: '#818cf8', rgb: '129,140,248',  label: 'Frontend',  icon: '⚛'  },
  hook:     { color: '#c084fc', rgb: '192,132,252',  label: 'Hook',      icon: '🪝'  },
  api:      { color: '#34d399', rgb: '52,211,153',   label: 'API',       icon: '🌐'  },
  module:   { color: '#fbbf24', rgb: '251,191,36',   label: 'Modul',     icon: '🐍'  },
  llm:      { color: '#a78bfa', rgb: '167,139,250',  label: 'LLM',       icon: '🤖'  },
  file:     { color: '#64748b', rgb: '100,116,139',  label: 'Datei',     icon: '📄'  },
  pipeline: { color: '#f97316', rgb: '249,115,22',   label: 'Pipeline',  icon: '⚙'   },
}

export function rgbA(type, alpha) {
  const cfg = TYPE_CFG[type] || TYPE_CFG.module
  return `rgba(${cfg.rgb}, ${alpha})`
}
