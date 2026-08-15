const actions = {
  preview: () => "preview",
  download: () => "download",
};

export function dispatchConfiguredAction(config: Map<string, string>) {
  const action = config.get("defaultAction");
  return actions[action]();
}
