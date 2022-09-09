import {
  Injectable,
  PreconditionFailedException,
  InternalServerErrorException,
  NotFoundException,
  Logger,
} from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { MoreThan, Repository } from "typeorm";
import { SnapshotEntity } from "../entities/snapshot.entity";
import axios from "axios";
import { randomUUID } from "crypto";
import { CommonService } from "../../common/common.service";

type SnapshotResponse = {
  blockId: string;
  context: string;
  height: number;
};

@Injectable()
export class FlowSnapshotService {
  private logger = new Logger(FlowSnapshotService.name);

  constructor(
    @InjectRepository(SnapshotEntity)
    private readonly snapshotRepository: Repository<SnapshotEntity>,
    private readonly commonService: CommonService
  ) {}

  async create(description: string) {
    // TODO(milestone-3): use value from emulator config object
    const snapshotId = randomUUID();
    const response = await this.createOrRevertSnapshotRequest(snapshotId);

    if (response.status !== 200) {
      this.logger.error(
        `Got ${response.status} response from emulator`,
        response.data
      );
      // Most likely reason for failure is that emulator wasn't started with "persist" flag
      throw new InternalServerErrorException("Failed to create snapshot");
    }

    const snapshotData = response.data as SnapshotResponse;

    const existingSnapshot = await this.snapshotRepository.findOneBy({
      blockId: snapshotData.blockId,
    });

    if (existingSnapshot) {
      throw new PreconditionFailedException(
        "Snapshot already exists at this block"
      );
    }

    const snapshot = new SnapshotEntity();
    snapshot.id = snapshotId;
    snapshot.blockId = snapshotData.blockId;
    snapshot.description = description;

    return this.snapshotRepository.save(snapshot);
  }

  async revertTo(blockId: string) {
    const existingSnapshot = await this.snapshotRepository.findOneBy({
      blockId,
    });

    if (!existingSnapshot) {
      throw new NotFoundException("Snapshot not found");
    }

    const response = await this.createOrRevertSnapshotRequest(
      existingSnapshot.id
    );

    if (response.status !== 200) {
      this.logger.error(
        `Got ${response.status} response from emulator`,
        response.data
      );
      throw new InternalServerErrorException("Failed to revert to snapshot");
    }

    await this.commonService.removeBlockchainData();

    return existingSnapshot;
  }

  findAllNewerThanTimestamp(timestamp: Date): Promise<SnapshotEntity[]> {
    return this.snapshotRepository.find({
      where: { createdAt: MoreThan(timestamp) },
      order: { createdAt: "DESC" },
    });
  }

  async findAll() {
    return this.snapshotRepository.find({
      order: { createdAt: "DESC" },
    });
  }

  private async createOrRevertSnapshotRequest(snapshotId: string) {
    // Docs: https://github.com/onflow/flow-emulator#managing-emulator-state
    return axios.get<SnapshotResponse>(
      `http://localhost:8080/emulator/snapshot/${snapshotId}`,
      // Prevent axios from throwing on certain http response codes
      // https://github.com/axios/axios/issues/41
      { validateStatus: () => true }
    );
  }
}
