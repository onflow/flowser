import { createContext, ReactNode, useContext } from "react";
import {
  FclArgumentWithMetadata,
  FlowAccount,
  FlowAccountKey,
  FlowAccountStorage,
  FlowBlock,
  FlowCliInfo,
  FlowContract,
  FlowEvent,
  FlowserWorkspace,
  FlowStateSnapshot,
  FlowTransaction,
  WorkspaceTemplate,
  IResourceIndexReader,
  ManagedProcessOutput,
  ParsedInteractionOrError,
  ManagedKeyPair,
  ManagedProcess
} from "@onflowser/api";
import { ScriptOutcome, TransactionOutcome } from "../interactions/core/core-types";
import { ChainID } from "@onflowser/core/src/flow-utils";
import { FlowNamesService } from "@onflowser/core/src/flow-names.service";

export interface ISnapshotService {
  list(): Promise<FlowStateSnapshot[]>;
  create(name: string): Promise<void>;
  jumpTo(name: string): Promise<void>;
  rollbackToHeight(height: number): Promise<void>;
}

export interface IWorkspaceService {
  remove(id: string): Promise<void>;
  close(id: string): Promise<void>;
  create(workspace: FlowserWorkspace): Promise<void>;
  update(workspace: FlowserWorkspace): Promise<void>;
  open(id: string): Promise<void>;
  list(): Promise<FlowserWorkspace[]>;
  findById(id: string): Promise<FlowserWorkspace | undefined>;
  getDefaultSettings(): Promise<FlowserWorkspace>;
}

export interface IInteractionService {
  parse(sourceCode: string): Promise<ParsedInteractionOrError>;
  getTemplates(): Promise<WorkspaceTemplate[]>;
  sendTransaction(
    request: SendTransactionRequest,
  ): Promise<TransactionOutcome>;
  executeScript(request: ExecuteScriptRequest): Promise<ScriptOutcome>;
}

export type SendTransactionRequest = {
  // TODO(web): These should probably be of type FlowAuthorizationFunction when generalizing for web version
  cadence: string;
  proposerAddress?: string;
  payerAddress?: string;
  authorizerAddresses?: string[];
  arguments: FclArgumentWithMetadata[];
};

export type ExecuteScriptRequest = {
  cadence: string;
  arguments: FclArgumentWithMetadata[];
};

export interface IFlowService {
  getIndexOfAddress(chainID: ChainID, address: string): Promise<number>;
}

export type FlowConfigAccount = {
  name: string;
  address: string;
  privateKey: string | undefined;
};

export type FlowConfigContract = {
  name: string;
  // Path relative to the project root dir.
  relativePath: string;
  absolutePath: string;
};

export interface IFlowConfigService {
  getAccounts(): Promise<FlowConfigAccount[]>;
  getContracts(): Promise<FlowConfigContract[]>;
}

export interface IFlowCliService {
  getFlowCliInfo(): Promise<FlowCliInfo>;
}

export interface IWalletService {
  createAccount(): Promise<void>;
  listKeyPairs(): Promise<ManagedKeyPair[]>;
}

interface IAnalyticsService {
  disable(): void;
  enable(): void;
  track(event: string, properties?: Record<string, unknown>): void;
}

interface IMonitoringService {
  captureError(error: unknown, options?: Record<string, unknown>): void;
}

export interface IProcessManagerService {
  listProcesses(): Promise<ManagedProcess[]>
  listLogsByProcessId(processId: string): Promise<ManagedProcessOutput[]>;
}

type ServiceRegistry = {
  interactionsService: IInteractionService;
  accountIndex: IResourceIndexReader<FlowAccount>;
  accountStorageIndex: IResourceIndexReader<FlowAccountStorage>;
  contractIndex: IResourceIndexReader<FlowContract>;
  transactionsIndex: IResourceIndexReader<FlowTransaction>;
  blocksIndex: IResourceIndexReader<FlowBlock>;
  eventsIndex: IResourceIndexReader<FlowEvent>;
  accountKeyIndex: IResourceIndexReader<FlowAccountKey>;
  // Optional services, as they may not be available/relevant in all environments.
  monitoringService?: IMonitoringService;
  analyticsService?: IAnalyticsService;
  processManagerService?: IProcessManagerService;
  flowService: IFlowService;
  flowCliService?: IFlowCliService;
  flowConfigService?: IFlowConfigService;
  walletService?: IWalletService;
  snapshotService?: ISnapshotService;
  workspaceService?: IWorkspaceService;
  flowNamesService?: FlowNamesService;
};

const ServiceRegistryContext = createContext<ServiceRegistry>(
  undefined as never,
);

type ServiceRegistryProviderProps = {
  children: ReactNode;
  services: ServiceRegistry;
};

export function ServiceRegistryProvider(props: ServiceRegistryProviderProps) {
  return (
    <ServiceRegistryContext.Provider value={props.services}>
      {props.children}
    </ServiceRegistryContext.Provider>
  );
}

export function useServiceRegistry(): ServiceRegistry {
  const context = useContext(ServiceRegistryContext);

  if (context === undefined) {
    throw new Error("ServiceRegistryContext not found");
  }

  return context;
}


export function useRequiredService<Key extends keyof ServiceRegistry>(name: Key): NonNullable<ServiceRegistry[Key]> {
  const registry = useServiceRegistry();

  const service = registry[name];

  if (service === undefined) {
    throw new Error(`Required service ${name} not found`)
  }

  return service;
}
