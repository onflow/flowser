import React, { ReactElement } from "react";
import Card from "../card/Card";
import classes from "./Table.module.scss";
import classNames from "classnames";
import {
  flexRender,
  getCoreRowModel,
  HeaderGroup,
  Row,
  TableOptions,
  useReactTable,
  RowData,
} from "@tanstack/react-table";
import { CommonUtils } from "../../utils/common-utils";
import { NoResults } from "../no-results/NoResults";
import FullScreenLoading from "../fullscreen-loading/FullScreenLoading";
import { DecoratedPollingEntity } from "../../contexts/timeout-polling.context";

type CustomTableProps<TData> = {
  renderCustomHeader?: (header: HeaderGroup<TableData<TData>>) => ReactElement;
  renderCustomRow?: (row: Row<TableData<TData>>) => ReactElement;
  headerRowClass?: string;
  bodyRowClass?: string;
  footerRowClass?: string;
  isInitialLoading?: boolean;
};

export type TableProps<TData> = Pick<
  TableOptions<TableData<TData>>,
  "data" | "columns"
> &
  CustomTableProps<TData> & {
    className?: string;
  };

export type TableData<TData> = DecoratedPollingEntity<TData> | TData;

declare module "@tanstack/table-core" {
  // https://tanstack.com/table/v8/docs/api/core/column-def#meta
  interface ColumnMeta<TData extends RowData, TValue> {
    // Can be used to assign a custom class name to a column.
    className?: string;
  }
}

function Table<TData>({
  isInitialLoading,
  columns,
  data,
  renderCustomRow,
  renderCustomHeader,
  headerRowClass,
  bodyRowClass,
  footerRowClass,
  className,
}: TableProps<TData>): ReactElement {
  const table = useReactTable<TableData<TData>>({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  if (!isInitialLoading && data.length === 0) {
    return <NoResults />;
  }

  if (isInitialLoading) {
    return <FullScreenLoading />;
  }

  return (
    <div className={classNames(classes.root, className)}>
      {table.getHeaderGroups().map((headerGroup) =>
        renderCustomHeader ? (
          renderCustomHeader(headerGroup)
        ) : (
          <Card
            className={classNames(classes.tableRow, headerRowClass)}
            key={headerGroup.id}
            variant="header-row"
          >
            {headerGroup.headers.map((header) => (
              <div
                key={header.id}
                className={header.column.columnDef.meta?.className}
              >
                {flexRender(
                  header.column.columnDef.header,
                  header.getContext()
                )}
              </div>
            ))}
          </Card>
        )
      )}
      {table.getRowModel().rows.map((row) =>
        renderCustomRow ? (
          renderCustomRow(row)
        ) : (
          <Card
            className={classNames(classes.tableRow, bodyRowClass)}
            key={row.id}
            showIntroAnimation={showIntroAnimation(row.original)}
            variant="table-line"
          >
            {row.getVisibleCells().map((cell) => (
              <div
                key={cell.id}
                className={cell.column.columnDef.meta?.className}
              >
                {flexRender(cell.column.columnDef.cell, cell.getContext())}
              </div>
            ))}
          </Card>
        )
      )}
      {table.getFooterGroups().map((footerGroup) => (
        <div
          className={classNames(classes.tableRow, footerRowClass)}
          key={footerGroup.id}
        >
          {footerGroup.headers.map((header) => (
            <div
              key={header.id}
              className={header.column.columnDef.meta?.className}
            >
              {flexRender(header.column.columnDef.footer, header.getContext())}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function showIntroAnimation<TData>(dataItem: TableData<TData>) {
  if (CommonUtils.isDecoratedPollingEntity(dataItem)) {
    return dataItem.isNew || dataItem.isUpdated;
  } else {
    return false;
  }
}

export default Table;
