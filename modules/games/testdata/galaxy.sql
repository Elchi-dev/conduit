-- The GOG Galaxy 2 tables the scanner reads (galaxy-2.0.db).
CREATE TABLE InstalledBaseProducts (productId INTEGER PRIMARY KEY, installationPath TEXT, installationDate TEXT);
CREATE TABLE LimitedDetails (id INTEGER PRIMARY KEY, productId INTEGER, title TEXT, images TEXT, languageId INTEGER);
CREATE TABLE GamePieceTypes (id INTEGER PRIMARY KEY, type TEXT);
CREATE TABLE GamePieces (releaseKey TEXT, gamePieceTypeId INTEGER, userId INTEGER, value TEXT);
CREATE TABLE GameTimes (userId INTEGER, releaseKey TEXT, minutesInGame INTEGER);
CREATE TABLE LastPlayedDates (userId INTEGER, gameReleaseKey TEXT, lastPlayedDate TEXT);
INSERT INTO InstalledBaseProducts VALUES (1207658924, 'C:\GOG Games\The Witcher 3 Wild Hunt GOTY', '2024-03-02 11:00:00'), (1495134320, 'C:\GOG Games\Disco Elysium', '2024-05-01 10:00:00');
INSERT INTO LimitedDetails VALUES (1, 1207658924, 'The Witcher 3: Wild Hunt - Game of the Year Edition', '{"background":"https://images.gog-statics.com/bg.jpg"}', 1);
INSERT INTO GamePieceTypes VALUES (1, 'originalTitle'), (2, 'originalImages'), (3, 'allGameReleases');
INSERT INTO GamePieces VALUES
  ('gog_1207658924', 2, 1, '{"background":"https://images.gog-statics.com/w3bg.webp","squareIcon":"https://images.gog-statics.com/w3sq.png","verticalCover":"https://images.gog-statics.com/w3vertical_342x482.jpg"}'),
  ('gog_1495134320', 1, 1, '{"title":"Disco Elysium - The Final Cut"}');
INSERT INTO GameTimes VALUES (1, 'gog_1207658924', 7380), (1, 'gog_1495134320', 95);
INSERT INTO LastPlayedDates VALUES (1, 'gog_1207658924', '2025-10-12 20:31:05');
