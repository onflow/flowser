import { Column, Entity, ManyToOne, PrimaryColumn } from "typeorm";
import { PollingEntity } from "../../common/entities/polling.entity";
import { AccountEntity } from "./account.entity";
import { ensurePrefixedAddress } from "../../utils";
import { FlowAccount, FlowKey } from "../../flow/services/flow-gateway.service";
import {
  AccountKey,
  HashAlgo,
  SignCurve,
} from "@flowser/types/generated/entities/accounts";

@Entity({ name: "keys" })
export class AccountKeyEntity extends PollingEntity {
  @PrimaryColumn()
  index: number;

  @PrimaryColumn()
  accountAddress: string;

  @Column()
  publicKey: string;

  @Column()
  signAlgo: SignCurve;

  @Column()
  hashAlgo: HashAlgo;

  @Column()
  weight: number;

  @Column()
  sequenceNumber: number;

  @Column()
  revoked: boolean;

  @ManyToOne(() => AccountEntity, (account) => account.storage)
  account: AccountEntity;

  toProto() {
    return AccountKey.fromPartial({
      index: this.index,
      accountAddress: this.accountAddress,
      publicKey: this.publicKey,
      signAlgo: this.signAlgo,
      hashAlgo: this.hashAlgo,
      weight: this.weight,
      sequenceNumber: this.sequenceNumber,
      revoked: this.revoked,
    });
  }

  static create(flowAccount: FlowAccount, flowKey: FlowKey) {
    const key = new AccountKeyEntity();
    key.index = flowKey.index;
    key.accountAddress = ensurePrefixedAddress(flowAccount.address);
    key.publicKey = flowKey.publicKey;
    key.signAlgo = flowKey.signAlgo;
    key.hashAlgo = flowKey.hashAlgo;
    key.weight = flowKey.weight;
    key.sequenceNumber = flowKey.sequenceNumber;
    key.revoked = flowKey.revoked;
    return key;
  }
}
