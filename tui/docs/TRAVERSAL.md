## Traversing an atom

Traversal queries begin with `atom`, followed by a primary node type from the below list.

| Name                | Comment                                                                             |
| ------------------- | ----------------------------------------------------------------------------------- |
| annotation          | Entire annotation                                                                   |
| annotationLiteral   | Literatal values in an annotation                                                   |
| annotationParameter | Parameter values                                                                    |
| call                | Call nodes                                                                          |
| configFile          | Configuration files                                                                 |
| file                | File                                                                                |
| identifier          | Identifier nodes                                                                    |
| imports             | Import nodes                                                                        |
| literal             | Literal nodes                                                                       |
| local               | Local variables                                                                     |
| method              | Method nodes                                                                        |
| ret                 | Return statements                                                                   |
| tag                 | Tag nodes                                                                           |
| typeDecl            | Type declarations                                                                   |
| typeRef             | Type references                                                                     |
| cfgNode             | Wrapper for multiple nodes such as annotation, call, control_structure, method, etc |
| declaration         | Wrapper for multiple noeds such as local, member, method, etc                       |

Example:

```scala
// List all annotations in the atom
atom.annotation.l

// List all files in the atom
atom.file.l

// Show the annotation list as json
atom.annotation.toJson
```

## annotation steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)
- fullName(pattern)

## annotationLiteral steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)

## annotationParameter steps

- code(pattern)

## call steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)
- methodFullName(pattern)
- signature(pattern)
- typeFullName(pattern)

### call traversal

- argument - All argument nodes
- callee - The called method(s). Needs a call resolver: `atom.call.name("exec").callee(using NoResolve).l`
- inCall - The surrounding call site of an argument/expression: `atom.call.name("<operator>.indirectIndexAccess").inCall.code.l`

Tip: to find every CALL SITE of a function by name (the usage, not the declaration), match on the
call directly — `atom.call.name("system")` or `atom.call.methodFullName(".*os\\.system.*")` — which
needs no resolver. The `atom_callsites` tool wraps exactly this.

## configFile steps

- name(string)
- content(string)

## file steps

- name(string)

## identifier steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- name(pattern)
- typeFullName(pattern)

## import steps

- code(pattern)
- importedAs(string)
- importedEntity(string)
- isExplicit(boolean)
- isWildcard(boolean)

## literal steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- typeFullName(pattern)

## local steps

- code(pattern)
- name(pattern)
- typeFullName(pattern)

## method steps

- code(pattern)
- filename(pattern)
- name(pattern)
- fullName(pattern)
- isExternal(boolean)
- signature(pattern)

### method traversal

- parameter - All MethodParameterIn nodes of the given method.
- literal - All literal nodes in the method.
- call - Outgoing call sites inside the method body (no resolver): `atom.method.name("main").call.l`

#### Call-graph steps (require a resolver)

These walk the call graph and need an implicit `ICallResolver` — pass `(using NoResolve)` for fast,
unresolved navigation:

- caller - Methods that CALL this method (incoming): `atom.method.name("exit").caller(using NoResolve).code.l`
- callee - Methods CALLED BY this method (outgoing): `atom.method.name("main").callee(using NoResolve).name.l`
- callIn - The incoming call SITES (Call nodes) of this method: `atom.method.name("exit").callIn(using NoResolve).code.l`

The `atom_callgraph` tool wraps caller/callee/calls and injects the resolver for you, so you rarely
need to write these by hand.

## ret steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)

## tag steps

- name(pattern)

## typeDecl steps

- code(pattern)
- filename(pattern)
- name(pattern)
- fullName(pattern)
- isExternal(boolean)

## typeRef steps

- argumentIndex(int)
- argumentName(pattern)
- code(pattern)
- typeFullName(pattern)

## cfgNode steps

- code(pattern)

### Control-flow & dominance steps

These operate on the control-flow and dominator trees of a method (no resolver needed). Anchor them
on a call matched by code, e.g. `atom.call.code(".*argc.*strcmp.*")`:

- controls - All nodes whose execution this node decides (this node is a guard/condition): `atom.call.code(".*argc.*strcmp.*").controls.code.l`
- controlledBy - All guard/condition nodes this node is control-dependent on (what must hold to reach it — check for missing auth/validation): `atom.call.codeExact("exit(42)").controlledBy.code.l`
- dominates - All nodes this node dominates (must run after it on every path): `atom.call.code(".*argc.*strcmp.*").dominates.code.l`
- dominatedBy - All nodes that dominate this node (must run before it on every path): `atom.call.codeExact("exit(42)").dominatedBy.code.l`
- postDominates - All nodes this node post-dominates: `atom.call.code(".*argc.*strcmp.*").postDominates.code.l`
- postDominatedBy - All nodes that post-dominate this node: `atom.call.codeExact("exit(42)").postDominatedBy.code.l`

The `atom_controlflow` tool wraps all six relations.

## declaration steps

- name(pattern)

## Helper step methods

Step methods accepting an integer would have variations such as Gt, Gte, Lt, Lte and Not to support integer operations.

Example:

```scala
atom.annotation.argumentIndexGt(1).l
```

Step methods accepting a string would have variations such as Exact and Not.

Example:

```scala
atom.annotation.argumentNameNot("foo").l
```

## Chaining step methods

If a step method return an iterator of type node then the method calls could be chained.

Example:

Parameters of all methods with the name `foo`.

```scala
atom.method.name("foo").parameter.l
```
