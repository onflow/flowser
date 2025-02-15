import {
  FclArgBuilder,
  FclTypeLookup,
  FclValue,
  FclValueUtils,
} from "./fcl-value";
import * as fcl from "@onflow/fcl";
import { FclArgumentWithMetadata } from "@onflowser/api";
import { HttpService } from "./http.service";

// https://docs.onflow.org/fcl/reference/api/#collectionguaranteeobject
export type FlowCollectionGuarantee = {
  collectionId: string;
  signatures: string[];
};

// https://docs.onflow.org/fcl/reference/api/#blockobject
export type FlowBlock = {
  id: string;
  parentId: string;
  height: number;
  timestamp: number;
  collectionGuarantees: FlowCollectionGuarantee[];
  blockSeals: any[];
  // TODO(milestone-x): "signatures" field is not present in block response
  // https://github.com/onflow/fcl-js/issues/1355
  signatures: string[];
};

// https://docs.onflow.org/fcl/reference/api/#keyobject
export type FlowKey = {
  index: number;
  publicKey: string;
  signAlgo: number;
  hashAlgo: number;
  weight: number;
  sequenceNumber: number;
  revoked: boolean;
};

// https://docs.onflow.org/fcl/reference/api/#accountobject
export type FlowAccount = {
  address: string;
  balance: number;
  code: string;
  contracts: Record<string, string>;
  keys: FlowKey[];
};

// https://docs.onflow.org/fcl/reference/api/#collectionobject
export type FlowCollection = {
  id: string;
  transactionIds: string[];
};

export type FlowTypeAnnotatedValue = {
  // https://developers.flow.com/tooling/fcl-js/api#ftype
  type: string;
  value: FclValue;
};

// https://docs.onflow.org/fcl/reference/api/#proposalkeyobject
export type FlowProposalKey = {
  address: string;
  keyId: number;
  sequenceNumber: number;
};

// https://docs.onflow.org/fcl/reference/api/#signableobject
export type FlowSignableObject = {
  address: string;
  keyId: number;
  signature: string;
};

// https://docs.onflow.org/fcl/reference/api/#transactionstatusobject
export type FlowTransactionStatus = {
  blockId: string;
  // https://developers.flow.com/tools/clients/fcl-js/api#transaction-statuses
  status: 0 | 1 | 2 | 3 | 4 | 5;
  statusString: string;
  statusCode: 1 | 0;
  errorMessage: string;
  events: FlowEvent[];
};

// https://docs.onflow.org/fcl/reference/api/#transactionobject
export type FlowTransaction = {
  id: string;
  script: string;
  args: FlowTypeAnnotatedValue[];
  referenceBlockId: string;
  gasLimit: number;
  proposalKey: FlowProposalKey;
  payer: string; // payer account address
  authorizers: string[]; // authorizers account addresses
  envelopeSignatures: FlowSignableObject[];
  payloadSignatures: FlowSignableObject[];
};

// https://developers.flow.com/cadence/language/crypto#signing-algorithms
export enum FlowSignatureAlgorithm {
  // Enum values must be kept unchanged.
  ECDSA_P256 = "1",
  ECDSA_secp256k1 = "2",
  BLS_BLS12_381 = "3",
}

// https://developers.flow.com/cadence/language/core-events
export enum FlowCoreEventType {
  ACCOUNT_CREATED = "flow.AccountCreated",
  ACCOUNT_KEY_ADDED = "flow.AccountKeyAdded",
  ACCOUNT_KEY_REMOVED = "flow.AccountKeyRemoved",
  ACCOUNT_CONTRACT_ADDED = "flow.AccountContractAdded",
  ACCOUNT_CONTRACT_UPDATED = "flow.AccountContractUpdated",
  ACCOUNT_CONTRACT_REMOVED = "flow.AccountContractRemoved",
  // TODO(account-linking): Add account inbox events
  //  https://developers.flow.com/cadence/language/core-events#inbox-value-published
}

type FlowEventInternal<Type, Data> = {
  transactionId: string;
  type: Type;
  transactionIndex: number;
  eventIndex: number;
  data: Data;
};

// https://developers.flow.com/cadence/language/core-events#account-key-added
export type FlowAccountKeyEvent = FlowEventInternal<
  FlowCoreEventType.ACCOUNT_KEY_ADDED | FlowCoreEventType.ACCOUNT_KEY_REMOVED,
  {
    address: string;
    publicKey: {
      // https://developers.flow.com/cadence/language/crypto#publickey
      publicKey: string[];
      signatureAlgorithm: {
        rawValue: FlowSignatureAlgorithm;
      };
    };
  }
>;

// https://developers.flow.com/cadence/language/core-events#account-contract-added
export type FlowAccountContractEvent = FlowEventInternal<
  | FlowCoreEventType.ACCOUNT_CONTRACT_UPDATED
  | FlowCoreEventType.ACCOUNT_CONTRACT_ADDED
  | FlowCoreEventType.ACCOUNT_CONTRACT_REMOVED,
  {
    address: string;
    codeHash: string[];
    // Contract name
    contract: string;
  }
>;

// https://developers.flow.com/cadence/language/core-events#account-created
export type FlowAccountEvent = FlowEventInternal<
  FlowCoreEventType.ACCOUNT_CREATED,
  { address: string }
>;

export type FlowAnyEvent = FlowEventInternal<
  `A.${string}.${string}.${string}`,
  Record<string, any>
>;

// https://docs.onflow.org/fcl/reference/api/#event-object
export type FlowEvent =
  | FlowAnyEvent
  | FlowAccountKeyEvent
  | FlowAccountEvent
  | FlowAccountContractEvent;

// https://developers.flow.com/tools/clients/fcl-js/api#authorization-function
export type FlowAuthorizationFunction = () => unknown;

type SendFlowTransactionOptions = {
  cadence: string;
  proposer: FlowAuthorizationFunction;
  payer: FlowAuthorizationFunction;
  authorizations: FlowAuthorizationFunction[];
  arguments: FclArgumentWithMetadata[];
};

type ExecuteFlowScriptOptions = {
  cadence: string;
  arguments: FclArgumentWithMetadata[];
};

type FlowTxUnsubscribe = () => void;

type FlowTxStatusCallback = (status: FlowTransactionStatus) => void;

type FlowTxSubscribe = (callback: FlowTxStatusCallback) => FlowTxUnsubscribe;

// https://developers.flow.com/tooling/fcl-js/api#returns-19
type FlowTxStatusSubscription = {
  subscribe: FlowTxSubscribe;
  onceFinalized: () => Promise<void>;
  onceExecuted: () => Promise<void>;
  onceSealed: () => Promise<void>;
};

type FlowGatewayConfig = {
  network: "local" | "canarynet" | "testnet" | "mainnet"
  accessNodeRestApiUrl: string;
  discoveryWalletUrl: string;
  flowJSON?: unknown;
};

export class FlowGatewayService {

  constructor(private readonly httpService: HttpService) {}

  public configure(config: FlowGatewayConfig): void {
    const configured = fcl
      .config({
        "accessNode.api": config.accessNodeRestApiUrl,
        "flow.network": config.network,
        "discovery.wallet": config.discoveryWalletUrl,
        "app.detail.icon": "https://flowser.dev/icon.png",
        "app.detail.title": "Flowser"
      });

    if (config.flowJSON) {
      configured.load({
        flowJSON: config.flowJSON,
      })
    }
  }

  public configureFlowJSON(flowJSON?: unknown) {
    fcl.config().load({ flowJSON })
  }

  public async executeScript<Result>(
    options: ExecuteFlowScriptOptions,
  ): Promise<Result> {
    return await fcl.query({
      cadence: options.cadence,
      args: (arg: FclArgBuilder, t: FclTypeLookup) => {
        const argumentFunction = FclValueUtils.getArgumentFunction(
          options.arguments,
        );
        return argumentFunction(arg, t);
      },
    });
  }

  /**
   * Sends the transaction and returns the transaction ID.
   *
   * https://developers.flow.com/tooling/fcl-js/transactions
   */
  public async sendTransaction(
    options: SendFlowTransactionOptions,
  ): Promise<{ transactionId: string }> {
    const transactionId = await fcl.mutate({
      cadence: options.cadence,
      args: (arg: FclArgBuilder, t: FclTypeLookup) => {
        const argumentFunction = FclValueUtils.getArgumentFunction(
          options.arguments,
        );
        return argumentFunction(arg, t);
      },
      proposer: options.proposer,
      authorizations: options.authorizations,
      payer: options.payer,
      limit: 9999,
    });

    return { transactionId };
  }

  public getTxStatusSubscription(
    transactionId: string,
  ): FlowTxStatusSubscription {
    return fcl.tx(transactionId);
  }

  public async getLatestBlock(): Promise<FlowBlock> {
    return fcl
      .send([
        fcl.getBlock(true), // Get latest sealed block
      ])
      .then(fcl.decode);
  }

  public async getBlockByHeight(height: number): Promise<FlowBlock> {
    return fcl
      .send([fcl.getBlock(), fcl.atBlockHeight(height)])
      .then(fcl.decode);
  }

  public async getBlockById(id: string): Promise<FlowBlock> {
    return fcl
      .send([fcl.getBlock(), fcl.atBlockId(id)])
      .then(fcl.decode);
  }

  public async getCollectionById(id: string): Promise<FlowCollection> {
    return fcl.send([fcl.getCollection(id)]).then(fcl.decode);
  }

  public async getTransactionById(id: string): Promise<FlowTransaction> {
    const transaction = await fcl
      .send([fcl.getTransaction(id)])
      .then(fcl.decode);
    return { ...transaction, id };
  }

  public async getTransactionStatusById(
    transactionId: string,
  ): Promise<FlowTransactionStatus> {
    return fcl.send([fcl.getTransactionStatus(transactionId)]).then(fcl.decode);
  }

  public async getAccount(address: string): Promise<FlowAccount> {
    const account = await fcl.send([fcl.getAccount(address)]).then(fcl.decode);
    // https://developers.flow.com/tools/fcl-js/reference/api#accountobject
    return { ...account, balance: account.balance / Math.pow(10, 8), address };
  }

  public async isRestApiReachable(): Promise<boolean> {
    const restServerUrl = await fcl.config.get("accessNode.api");

    if (!restServerUrl) {
      throw new Error("accessNode.api not configured");
    }

    return this.httpService.isReachable(restServerUrl);
  }

  public async isDiscoveryWalletReachable(): Promise<boolean> {
    const discoveryWalletUrl = await fcl.config.get("discovery.wallet");

    if (!discoveryWalletUrl) {
      throw new Error("discovery.wallet not configured");
    }

    return this.httpService.isReachable(discoveryWalletUrl);
  }
}
