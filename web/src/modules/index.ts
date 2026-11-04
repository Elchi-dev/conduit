import type { ComponentType } from "react";
import { GamesLibrary } from "./games/GamesLibrary";
import { StandardsStudio } from "./standards/Studio";

/**
 * Custom pages for modules that need more than the schema-driven screen.
 * The instance page shows the module's page in place of its action list,
 * with a switch back to the plain actions.
 */
export const modulePages: Record<string, ComponentType<{ instance: string }>> = {
  games: GamesLibrary,
  standards: StandardsStudio,
};
