CREATE TABLE Directories (
  DirectoryID              STRING(100) NOT NULL,
  Map                      BYTES(MAX),
  Log                      BYTES(MAX),
  VRFPublicKey             BYTES(MAX),
  VRFPrivateKey            BYTES(MAX),
  MinInterval              INT64,
  MaxInterval              INT64,
  Deleted                  BOOL,
  DeleteTime               TIMESTAMP,
) PRIMARY KEY (DirectoryID);

CREATE TABLE LogStatus(
  DirectoryID          STRING(100) NOT NULL,
  LogID                INT64 NOT NULL,
  WriteToLog           BOOL NOT NULL,
) PRIMARY KEY (DirectoryID, LogID),
  INTERLEAVE IN PARENT Directories ON DELETE CASCADE;

CREATE TABLE Batches(
  DirectoryID          STRING(100) NOT NULL,
  Revision             INT64 NOT NULL,
  Meta                 BYTES(1024),
) PRIMARY KEY (DirectoryID, Revision),
  INTERLEAVE IN PARENT Directories ON DELETE CASCADE;

CREATE TABLE Mutations (
  DirectoryID           STRING(100) NOT NULL,
  LogID                 INT64 NOT NULL,
  Timestamp             TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  LocalID               INT64 NOT NULL,
  Mutation              BYTES(MAX) NOT NULL,
) PRIMARY KEY(DirectoryID, LogID, Timestamp, LocalID),
  INTERLEAVE IN PARENT Directories ON DELETE CASCADE;
