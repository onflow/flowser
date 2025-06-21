import { ec as EC } from "elliptic";
import { SHA3 } from "sha3";
import { FlowCliService } from "./flow-cli.service";
import {
  ensurePrefixedAddress,
  FlowAuthorizationFunction,
  FlowGatewayService,
  signMessageWithPrivateKeyHex,
  sansPrefix,
  withPrefix
} from "@onflowser/core";
import { FclArgumentWithMetadata } from "@onflowser/api";
import { PersistentStorage } from "@onflowser/core/src/persistent-storage";

const fcl = require("@onflow/fcl");

export interface SendTransactionRequest {
  cadence: string;
  /** Signer roles: https://developers.flow.com/concepts/start-here/transaction-signing#signer-roles */
  proposerAddress: string;
  payerAddress: string;
  authorizerAddresses: string[];
  arguments: FclArgumentWithMetadata[];
}

export interface SendTransactionResponse {
  transactionId: string;
}

type CreateAccountRequest = {
  workspacePath: string;
};

const ec: EC = new EC("p256");

// https://developers.flow.com/tooling/flow-cli/accounts/create-accounts#key-weight
const defaultKeyWeight = 1000;

export type ManagedKeyPair = {
  address: string;
  publicKey: string;
  privateKey: string;
};

// TODO(restructure-followup): Should we import existing accounts from flow.json?
export class WalletService {
  private userServiceKeyPair: ManagedKeyPair | null = null;
  private actualUserServicePrivateKey: string | null = null;

  constructor(
    private readonly cliService: FlowCliService,
    private readonly flowGateway: FlowGatewayService,
    private readonly storageService: PersistentStorage,
  ) {}

  public setUserServiceAccount(keyPair: ManagedKeyPair | null, actualPrivateKey: string | null): void {
    this.userServiceKeyPair = keyPair;
    this.actualUserServicePrivateKey = actualPrivateKey;
  }

  public async sendTransaction(
    request: SendTransactionRequest,
  ): Promise<SendTransactionResponse> {
    const uniqueRoleAddresses = new Set([
      request.proposerAddress,
      request.payerAddress,
      ...request.authorizerAddresses,
    ]);
    const managedKeyPairs = await this.listKeyPairs();
    const authorizationFunctions = await Promise.all(
      Array.from(uniqueRoleAddresses).map(
        async (address): Promise<[string, FlowAuthorizationFunction]> => [
          address,
          await this.withAuthorization({ address, managedKeyPairs }),
        ],
      ),
    );

    function getAuthFunction(address: string) {
      const authFunction = authorizationFunctionsByAddress.get(address);
      if (authFunction === undefined) {
        throw new Error(`Authorization function not found for: ${address}`);
      }
      return authFunction;
    }
    const authorizationFunctionsByAddress = new Map(authorizationFunctions);

    return this.flowGateway.sendTransaction({
      cadence: request.cadence,
      proposer: getAuthFunction(request.proposerAddress),
      payer: getAuthFunction(request.payerAddress),
      authorizations: request.authorizerAddresses.map((address) =>
        getAuthFunction(address),
      ),
      arguments: request.arguments,
    });
  }

  // Returns undefined if provided account doesn't exist.
  private async withAuthorization(options: {
    address: string;
    managedKeyPairs: ManagedKeyPair[];
  }): Promise<FlowAuthorizationFunction> {
    const { address, managedKeyPairs } = options;
    // Check if this is the user service account and its actual private key is known
    if (
      this.userServiceKeyPair &&
      address === this.userServiceKeyPair.address &&
      this.actualUserServicePrivateKey
    ) {
      const account = await this.flowGateway.getAccount(address);
      // Find the keyId for the user service account's public key
      const serviceKey = account.keys.find(
        (key) => key.publicKey === this.userServiceKeyPair!.publicKey,
      );
      const keyIdToUse = serviceKey?.index;

      if (keyIdToUse === undefined) {
        throw new Error(
          `Public key ${this.userServiceKeyPair.publicKey} not found on account ${address} for user service account.`,
        );
      }
      const currentUserServicePrivateKey = this.actualUserServicePrivateKey;

      return async (fclAccount: Record<string, unknown> = {}) => ({
        ...fclAccount,
        tempId: `${address}-user-service-key`,
        addr: sansPrefix(address),
        keyId: keyIdToUse,
        signingFunction: async (signable: { message: string }) => ({
          addr: withPrefix(address),
          keyId: keyIdToUse,
          signature: signMessageWithPrivateKeyHex(
            currentUserServicePrivateKey,
            signable.message,
          ),
        }),
      });
    } else {
      // Existing logic for keys managed by WalletService's storage
      const managedKeyPairsOfAccount = managedKeyPairs.filter(
        (e) => e.address === address,
      );

      if (managedKeyPairsOfAccount.length === 0) {
        throw new Error(`Private keys not found for account: ${address} in WalletService storage.`);
      }

      const managedKeyToUse = managedKeyPairsOfAccount[0];

      const account = await this.flowGateway.getAccount(address);
      const associatedPublicKey = account.keys.find(
        (key) => key.publicKey === managedKeyToUse.publicKey,
      );

      if (!associatedPublicKey) {
        throw new Error(
          `Associated public key ${managedKeyToUse.publicKey} not found on account ${address} (from WalletService storage).`,
        );
      }

      const authn: FlowAuthorizationFunction = (
        fclAccount: Record<string, unknown> = {},
      ) => ({
        ...fclAccount,
        tempId: `${address}-${managedKeyToUse.privateKey}`,
        addr: fcl.sansPrefix(address),
        keyId: associatedPublicKey.index,
        signingFunction: (signable: any) => {
          if (!managedKeyToUse.privateKey || managedKeyToUse.privateKey === "managed-by-workspace-settings") {
            // This condition should ideally not be met if the above user service key path was taken.
            // If it's the placeholder, it means we expected it to be handled by the user service key logic.
            throw new Error(`Private key for ${address} is a placeholder or missing; it should be handled by user service key logic.`);
          }
          return {
            addr: fcl.withPrefix(address),
            keyId: associatedPublicKey.index,
            signature: this.signWithPrivateKey(
              managedKeyToUse.privateKey,
              signable.message,
            ),
          };
        },
      });

      return authn;
    }
  }

  public async synchronizeIndex() {
    const managedKeyPairs = await this.listKeyPairs();
    const associatedAccountResults = await Promise.allSettled(
      managedKeyPairs.map((keyPair) =>
        this.flowGateway.getAccount(keyPair.address),
      ),
    );
    const validKeyPairLookupByPublicKey = new Set(
      associatedAccountResults
        .map((result) => {
          if (result.status === "fulfilled") {
            return result.value.keys.map((key) => key.publicKey);
          } else {
            return [];
          }
        })
        .flat(),
    );
    await this.writeKeyPairs(
      managedKeyPairs.filter((keyPair) =>
        validKeyPairLookupByPublicKey.has(keyPair.publicKey),
      ),
    );
  }

  public async createAccount(options: CreateAccountRequest): Promise<void> {
    const generatedKeyPair = await this.cliService.generateKey({
      projectRootPath: options.workspacePath,
    });
    const generatedAccount = await this.cliService.createAccount({
      projectRootPath: options.workspacePath,
      keys: [
        {
          weight: defaultKeyWeight,
          publicKey: generatedKeyPair.public,
        },
      ],
    });

    const existingKeyPairs = await this.listKeyPairs();
    await this.writeKeyPairs([
      ...existingKeyPairs,
      {
        address: ensurePrefixedAddress(generatedAccount.address),
        privateKey: generatedKeyPair.private,
        publicKey: generatedKeyPair.public,
      },
    ]);
  }

  private signWithPrivateKey(privateKey: string, message: string) {
    const key = ec.keyFromPrivate(Buffer.from(privateKey, "hex"));
    const sig = key.sign(this.hashMessage(message));
    const n = 32;
    const r = sig.r.toArrayLike(Buffer, "be", n);
    const s = sig.s.toArrayLike(Buffer, "be", n);
    return Buffer.concat([r, s]).toString("hex");
  }

  private hashMessage(msg: string) {
    const sha = new SHA3(256);
    sha.update(Buffer.from(msg, "hex"));
    return sha.digest();
  }

  public async listKeyPairs() {
    const data = await this.storageService.read();
    let keyPairs = JSON.parse(data ?? "[]") as ManagedKeyPair[];

    if (this.userServiceKeyPair) {
      // Avoid duplicates if the address is already somehow in storage
      keyPairs = keyPairs.filter(kp => kp.address !== this.userServiceKeyPair!.address);
      keyPairs.push(this.userServiceKeyPair);
    }

    return keyPairs;
  }

  private async writeKeyPairs(keyPairs: ManagedKeyPair[]) {
    await this.storageService.write(JSON.stringify(keyPairs));
  }
}
