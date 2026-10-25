/**
 * A small parser for GitHub Actions expressions, enough to read `if:`
 * conditions. Context names are case-insensitive in GitHub, so paths are
 * lower-cased; `a['b']` becomes `a.b` and any other index becomes `*`.
 * Anything it does not model (such as a property of a function's result)
 * parses as `other`, which callers treat as unknown.
 */
export type Expr =
  | { type: "literal"; value: string | number | boolean | null }
  | { type: "ref"; path: string }
  | { type: "call"; name: string; args: Expr[] }
  | { type: "not"; operand: Expr }
  | { type: "binary"; op: BinaryOp; left: Expr; right: Expr }
  | { type: "other" };

export type BinaryOp = "||" | "&&" | "==" | "!=" | "<" | "<=" | ">" | ">=";

type Token =
  { t: "str"; v: string } | { t: "num"; v: number } | { t: "id"; v: string } | { t: "op"; v: string };

const tokenRE =
  /\s*(?:'((?:[^']|'')*)'|(\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_-]*)|(&&|\|\||==|!=|<=|>=|[<>!().,[\]*]))/y;

function tokenize(text: string): Token[] | null {
  const tokens: Token[] = [];
  tokenRE.lastIndex = 0;
  while (tokenRE.lastIndex < text.length) {
    if (/^\s*$/.test(text.slice(tokenRE.lastIndex))) break;
    const m = tokenRE.exec(text);
    if (!m) return null;
    if (m[1] !== undefined) tokens.push({ t: "str", v: m[1].replaceAll("''", "'") });
    else if (m[2] !== undefined) tokens.push({ t: "num", v: Number(m[2]) });
    else if (m[3] !== undefined) tokens.push({ t: "id", v: m[3] });
    else tokens.push({ t: "op", v: m[4] ?? "" });
  }
  return tokens;
}

class Parser {
  private i = 0;
  constructor(private readonly tokens: Token[]) {}

  private peek(): Token | undefined {
    return this.tokens[this.i];
  }

  private isOp(v: string): boolean {
    const t = this.peek();
    return t?.t === "op" && t.v === v;
  }

  private expect(v: string): void {
    if (!this.isOp(v)) throw new SyntaxError(`expected ${v}`);
    this.i++;
  }

  parse(): Expr {
    const e = this.or();
    if (this.i !== this.tokens.length) throw new SyntaxError("trailing tokens");
    return e;
  }

  private binary(ops: string[], next: () => Expr): Expr {
    let left = next();
    for (;;) {
      const t = this.peek();
      if (t?.t !== "op" || !ops.includes(t.v)) return left;
      this.i++;
      left = { type: "binary", op: t.v as BinaryOp, left, right: next() };
    }
  }

  private or(): Expr {
    return this.binary(["||"], () => this.and());
  }

  private and(): Expr {
    return this.binary(["&&"], () => this.equality());
  }

  private equality(): Expr {
    return this.binary(["==", "!="], () => this.comparison());
  }

  private comparison(): Expr {
    return this.binary(["<", "<=", ">", ">="], () => this.unary());
  }

  private unary(): Expr {
    if (this.isOp("!")) {
      this.i++;
      return { type: "not", operand: this.unary() };
    }
    return this.primary();
  }

  private primary(): Expr {
    const t = this.peek();
    if (!t) throw new SyntaxError("unexpected end");
    this.i++;
    if (t.t === "str" || t.t === "num") return { type: "literal", value: t.v };
    if (t.t === "op") {
      if (t.v !== "(") throw new SyntaxError(`unexpected ${t.v}`);
      const e = this.or();
      this.expect(")");
      return this.member(e);
    }
    const word = t.v.toLowerCase();
    if (word === "true" || word === "false") return { type: "literal", value: word === "true" };
    if (word === "null") return { type: "literal", value: null };
    if (this.isOp("(")) {
      this.i++;
      const args: Expr[] = [];
      if (!this.isOp(")")) {
        args.push(this.or());
        while (this.isOp(",")) {
          this.i++;
          args.push(this.or());
        }
      }
      this.expect(")");
      return this.member({ type: "call", name: word, args });
    }
    return this.member({ type: "ref", path: word });
  }

  /** Property access and indexing after a primary expression. */
  private member(base: Expr): Expr {
    const parts: string[] = [];
    for (;;) {
      if (this.isOp(".")) {
        this.i++;
        const t = this.peek();
        if (t?.t === "id") parts.push(t.v.toLowerCase());
        else if (t?.t === "op" && t.v === "*") parts.push("*");
        else throw new SyntaxError("expected a property name");
        this.i++;
      } else if (this.isOp("[")) {
        this.i++;
        const t = this.peek();
        const index = this.or();
        this.expect("]");
        parts.push(index.type === "literal" && t?.t === "str" ? String(index.value).toLowerCase() : "*");
      } else {
        break;
      }
    }
    if (parts.length === 0) return base;
    if (base.type !== "ref") return { type: "other" };
    return { type: "ref", path: [base.path, ...parts].join(".") };
  }
}

/** Parses an expression (without the surrounding `${{ }}`), or returns null. */
export function parseExpression(text: string): Expr | null {
  const tokens = tokenize(text);
  if (!tokens || tokens.length === 0) return null;
  try {
    return new Parser(tokens).parse();
  } catch {
    return null;
  }
}

/**
 * The expression text of an `if:` value: `${{ x }}` is unwrapped, a bare
 * condition is taken as is and YAML booleans are passed through. Returns null
 * for values it cannot read, such as text mixed with several expressions.
 */
export function conditionText(value: unknown): string | boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return null;
  const text = value.trim();
  const wrapped = /^\$\{\{([\s\S]*)\}\}$/.exec(text);
  if (wrapped) {
    const inner = wrapped[1] ?? "";
    return inner.includes("${{") || inner.includes("}}") ? null : inner.trim();
  }
  return text.includes("${{") ? null : text;
}
