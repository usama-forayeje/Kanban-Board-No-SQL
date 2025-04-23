export const TaskStatusEnum = {
  TODO: "todo",
  IN_PROGRESS: "in_progress",
  DONE: "done",
};

export const AvailableTaskStatuses = Object.values(TaskStatusEnum);

export const userStatusEnum = {
  ACTIVE: "active",
  INACTIVE: "inactive",
  BANNED: "banned",
};

export const AvailableUserStatuses = Object.values(userStatusEnum);


export const taskPriorityEnum = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

export const AvailableTaskPriorityStatuses = Object.values(taskPriorityEnum);
