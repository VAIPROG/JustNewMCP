export const TASK_STATUSES = ["pending", "in_progress", "completed", "blocked"] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

export interface Task {
  id: string;
  title: string;
  status: TaskStatus;
  dependencies: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

type TaskInput = Partial<Pick<Task, "title" | "status" | "dependencies" | "notes">>;

export class TaskManager {
  private readonly tasks = new Map<string, Task>();

  create(input: TaskInput & Pick<Task, "title">): Task {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const task: Task = {
      id,
      title: input.title,
      status: input.status ?? "pending",
      dependencies: this.validateDependencies(id, input.dependencies ?? []),
      notes: input.notes ?? "",
      createdAt: now,
      updatedAt: now,
    };
    this.tasks.set(id, task);
    return structuredClone(task);
  }

  update(id: string, input: TaskInput): Task {
    const current = this.requireTask(id);
    const task: Task = {
      ...current,
      title: input.title ?? current.title,
      status: input.status ?? current.status,
      dependencies: input.dependencies === undefined
        ? current.dependencies
        : this.validateDependencies(id, input.dependencies),
      notes: input.notes ?? current.notes,
      updatedAt: new Date().toISOString(),
    };
    this.tasks.set(id, task);
    return structuredClone(task);
  }

  list(): Task[] {
    return structuredClone([...this.tasks.values()]);
  }

  get(id: string): Task {
    return structuredClone(this.requireTask(id));
  }

  private requireTask(id: string): Task {
    const task = this.tasks.get(id);
    if (!task) throw new Error(`Task not found: ${id}`);
    return task;
  }

  private validateDependencies(id: string, ids: string[]): string[] {
    const dependencies = [...new Set(ids)];
    const remaining = [...dependencies];
    const visited = new Set<string>();

    while (remaining.length > 0) {
      const dependency = remaining.pop()!;
      if (dependency === id) {
        throw new Error("Task dependencies must not form a cycle.");
      }
      if (visited.has(dependency)) continue;
      visited.add(dependency);
      for (const ancestor of this.requireTask(dependency).dependencies) {
        remaining.push(ancestor);
      }
    }
    return dependencies;
  }
}

export class PlanMode {
  private state: { active: boolean; summary?: string } = { active: false };

  get active(): boolean {
    return this.state.active;
  }

  enter(summary = this.state.summary) {
    this.state = summary === undefined ? { active: true } : { active: true, summary };
    return { ...this.state };
  }

  exit(summary = this.state.summary) {
    this.state = { active: false };
    return summary === undefined ? { ...this.state } : { ...this.state, summary };
  }
}
