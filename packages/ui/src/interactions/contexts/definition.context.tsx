import React, {
  createContext,
  ReactElement,
  ReactNode,
  useContext,
} from "react";
import { useInteractionRegistry } from "./interaction-registry.context";
import {
  FclValueLookupByIdentifier,
  InteractionDefinition,
} from "../core/core-types";
import { ParsedInteraction } from "@onflowser/api";
import { FclValue } from "@onflowser/core";
import { useGetParsedInteraction } from "../../api";
import { FlixTemplate, useFlixSearch } from "../../hooks/use-flix";

type InteractionDefinitionManager = InteractionParameterBuilder & {
  isParsing: boolean;
  parseError: string | undefined;
  flixTemplate: FlixTemplate | undefined;
  parsedInteraction: ParsedInteraction | undefined;
  definition: InteractionDefinition;
  partialUpdate: (definition: Partial<InteractionDefinition>) => void;
};

export type InteractionParameterBuilder = {
  fclValuesByIdentifier: FclValueLookupByIdentifier;
  setFclValue: (identifier: string, value: FclValue) => void;
};

const Context = createContext<InteractionDefinitionManager>(undefined as never);

export function InteractionDefinitionManagerProvider(props: {
  definition: InteractionDefinition;
  children: ReactNode;
}): ReactElement {
  const { definition } = props;
  const { update } = useInteractionRegistry();
  const { data, isLoading } = useGetParsedInteraction(definition);
  const fclValuesByIdentifier = definition.fclValuesByIdentifier;
  const { data: flixTemplate } = useFlixSearch({
    interaction: definition,
  })

  function partialUpdate(newDefinition: Partial<InteractionDefinition>) {
    update({ ...definition, ...newDefinition });
  }

  function setFclValue(identifier: string, value: FclValue) {
    const oldMapping = definition.fclValuesByIdentifier;
    const newMapping = new Map(oldMapping);
    newMapping.set(identifier, value);
    update({
      ...definition,
      fclValuesByIdentifier: newMapping,
    });
  }

  return (
    <Context.Provider
      value={{
        definition,
        flixTemplate: flixTemplate ?? undefined,
        parsedInteraction: data?.interaction,
        partialUpdate,
        setFclValue,
        fclValuesByIdentifier,
        parseError: data?.error,
        isParsing: isLoading,
      }}
    >
      {props.children}
    </Context.Provider>
  );
}

export function useInteractionDefinitionManager(): InteractionDefinitionManager {
  const context = useContext(Context);

  if (context === undefined) {
    throw new Error("Interaction definition registry context not found");
  }

  return context;
}
