import Handlebars from 'handlebars';

const templateCache = new Map<string, HandlebarsTemplateDelegate>();

function compileCached(name: string, source: string): HandlebarsTemplateDelegate {
  const cached = templateCache.get(name);
  if (cached) return cached;
  const compiled = Handlebars.compile(source);
  templateCache.set(name, compiled);
  return compiled;
}

export function renderTemplate(
  name: string,
  source: string,
  data: Record<string, unknown>,
): string {
  const template = compileCached(name, source);
  return template(data);
}
