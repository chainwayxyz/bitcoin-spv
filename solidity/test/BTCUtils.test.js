/* global artifacts contract before it assert */
const BN = require('bn.js');

/* eslint-disable-next-line no-unresolved */
const vectors = require('./testVectors.json');

const BTCUtilsDelegate = artifacts.require('BTCUtilsTest');

const {
  lastBytes,
  lastBytesError,
  reverseEndianness,
  bytesToUint,
  hash160,
  hash256,
  hash256MerkleStep,
  extractOutpoint,
  extractInputTxIdLE,
  extractTxIndexLE,
  extractSequenceLEWitness,
  extractSequenceWitness,
  extractSequenceLELegacy,
  extractSequenceLegacy,
  extractSequenceLegacyError,
  extractHash,
  extractHashError,
  extractOpReturnData,
  extractOpReturnDataError,
  extractInputAtIndex,
  extractInputAtIndexError,
  isLegacyInput,
  extractValueLE,
  extractValue,
  determineInputLength,
  extractScriptSig,
  extractScriptSigError,
  extractScriptSigLen,
  validateVin,
  validateVout,
  determineOutputLength,
  extractOutputAtIndex,
  extractOutputAtIndexError,
  extractMerkleRootLE,
  extractTarget,
  extractPrevBlockLE,
  extractTimestamp,
  verifyHash256Merkle,
  determineVarIntDataLength,
  parseVarInt,
  parseVarIntError,
  retargetAlgorithm
} = vectors;

contract('BTCUtils', () => {
  let instance;

  before(async () => {
    instance = await BTCUtilsDelegate.new();
  });

  it('gets the last bytes correctly', async () => {
    for (let i = 0; i < lastBytes.length; i += 1) {
      await instance.lastBytes(lastBytes[i].input.bytes, lastBytes[i].input.num);
      const res = await instance.lastBytes.call(lastBytes[i].input.bytes, lastBytes[i].input.num);
      assert.strictEqual(res, lastBytes[i].output);
    }
  });

  it('errors if slice is larger than the bytearray', async () => {
    for (let i = 0; i < lastBytesError.length; i += 1) {
      try {
        await instance.lastBytes(lastBytesError[i].input.bytes, lastBytesError[i].input.num);
        assert(false, 'expected an errror');
      } catch (e) {
        const err = (lastBytesError[i].solidityError
          ? lastBytesError[i].solidityError : lastBytesError[i].errorMessage);
        assert.include(e.message, err);
      }
    }
  });

  it('reverses endianness', async () => {
    for (let i = 0; i < reverseEndianness.length; i += 1) {
      await instance.reverseEndianness(reverseEndianness[i].input);
      const res = await instance.reverseEndianness.call(reverseEndianness[i].input);
      assert.strictEqual(res, reverseEndianness[i].output);
    }
  });

  it('converts big-endian bytes to integers', async () => {
    for (let i = 0; i < bytesToUint.length; i += 1) {
      await instance.bytesToUint(bytesToUint[i].input);
      const res = await instance.bytesToUint.call(bytesToUint[i].input);
      assert(res, new BN(bytesToUint[i].output, 10));
    }

    // max uint256: (2^256)-1
    const res = await instance.bytesToUint.call(`0x${'ff'.repeat(32)}`);
    assert(
      res, new BN('115792089237316195423570985008687907853269984665640564039457584007913129639935', 10)
    );
  });

  it('implements bitcoin\'s hash160', async () => {
    for (let i = 0; i < hash160.length; i += 1) {
      await instance.hash160(hash160[i].input);
      const res = await instance.hash160.call(hash160[i].input);
      assert.strictEqual(res, hash160[i].output);
    }
  });

  it('implements bitcoin\'s hash256', async () => {
    for (let i = 0; i < hash256.length; i += 1) {
      await instance.hash256(hash256[i].input);
      const res = await instance.hash256.call(hash256[i].input);
      assert.strictEqual(res, hash256[i].output);
    }
  });

  it('implements hash256MerkleStep', async () => {
    for (let i = 0; i < hash256MerkleStep.length; i += 1) {
      /* eslint-disable-next-line */
      await instance._hash256MerkleStep(
        hash256MerkleStep[i].input[0],
        hash256MerkleStep[i].input[1]
      );
      const res = await instance._hash256MerkleStep.call(
        hash256MerkleStep[i].input[0],
        hash256MerkleStep[i].input[1]
      );
      assert.strictEqual(res, hash256MerkleStep[i].output);
    }
  });

  it('extracts a sequence from a witness input as LE and int', async () => {
    for (let i = 0; i < extractSequenceLEWitness.length; i += 1) {
      await instance.extractSequenceLEWitness(extractSequenceLEWitness[i].input);
      const res = await instance.extractSequenceLEWitness.call(extractSequenceLEWitness[i].input);
      assert.strictEqual(res, extractSequenceLEWitness[i].output);
    }

    for (let i = 0; i < extractSequenceWitness.length; i += 1) {
      await instance.extractSequenceWitness(extractSequenceWitness[i].input);
      const res = await instance.extractSequenceWitness.call(extractSequenceWitness[i].input);
      assert(res.eq(new BN(extractSequenceWitness[i].output, 16)));
    }
  });

  it('extracts a sequence from a legacy input as LE and int', async () => {
    for (let i = 0; i < extractSequenceLELegacy.length; i += 1) {
      await instance.extractSequenceLELegacy(extractSequenceLELegacy[i].input);
      const res = await instance.extractSequenceLELegacy.call(extractSequenceLELegacy[i].input);
      assert.strictEqual(res, extractSequenceLELegacy[i].output);
    }

    for (let i = 0; i < extractSequenceLegacy.length; i += 1) {
      await instance.extractSequenceLegacy(extractSequenceLegacy[i].input);
      const res = await instance.extractSequenceLegacy.call(extractSequenceLegacy[i].input);
      assert(res.eq(new BN(extractSequenceLegacy[i].output, 16)));
    }
  });

  it('errors on bad varints in extractSequenceLegacy', async () => {
    for (let i = 0; i < extractSequenceLegacyError.length; i += 1) {
      try {
        await instance.extractSequenceLegacy(
          extractSequenceLegacyError[i].input
        );
        assert(false, 'expected an error');
      } catch (e) {
        assert.include(e.message, extractSequenceLegacyError[i].solidityError);
      }
    }
  });

  it('extracts an outpoint as bytes', async () => {
    for (let i = 0; i < extractOutpoint.length; i += 1) {
      await instance.extractOutpoint(extractOutpoint[i].input);
      const res = await instance.extractOutpoint.call(extractOutpoint[i].input);
      assert.strictEqual(res, extractOutpoint[i].output);
    }
  });

  it('extracts an outpoint txid', async () => {
    for (let i = 0; i < extractInputTxIdLE.length; i += 1) {
      await instance.extractInputTxIdLE(extractInputTxIdLE[i].input);
      const res = await instance.extractInputTxIdLE.call(extractInputTxIdLE[i].input);
      assert.strictEqual(res, extractInputTxIdLE[i].output);
    }
  });

  it('extracts an outpoint tx index LE', async () => {
    for (let i = 0; i < extractTxIndexLE.length; i += 1) {
      await instance.extractTxIndexLE(extractTxIndexLE[i].input);
      const res = await instance.extractTxIndexLE.call(extractTxIndexLE[i].input);
      assert.strictEqual(res, extractTxIndexLE[i].output);
    }
  });

  it('extracts the hash from a standard output', async () => {
    for (let i = 0; i < extractHash.length; i += 1) {
      await instance.extractHash(extractHash[i].input);
      const res = await instance.extractHash.call(extractHash[i].input);
      assert.strictEqual(res, extractHash[i].output);
    }

    for (let i = 0; i < extractHashError.length; i += 1) {
      try {
        await instance.extractHash(extractHashError[i].input);
        assert(false, 'expected an error');
      } catch (e) {}
    }
  });

  it('extracts the value as LE and int', async () => {
    for (let i = 0; i < extractValueLE.length; i += 1) {
      await instance.extractValueLE(extractValueLE[i].input);
      const res = await instance.extractValueLE.call(extractValueLE[i].input);
      assert.strictEqual(res, extractValueLE[i].output);
    }

    for (let i = 0; i < extractValue.length; i += 1) {
      await instance.extractValue(extractValue[i].input);
      const res = await instance.extractValue.call(extractValue[i].input);
      assert(res.eq(new BN(extractValue[i].output, 16)));
    }
  });

  it('determines input length', async () => {
    for (let i = 0; i < determineInputLength.length; i += 1) {
      await instance.determineInputLength(determineInputLength[i].input);
      const res = await instance.determineInputLength.call(determineInputLength[i].input);
      assert(res.eq(new BN(determineInputLength[i].output, 10)));
    }
  });

  it('extracts op_return data blobs', async () => {
    for (let i = 0; i < extractOpReturnData.length; i += 1) {
      await instance.extractOpReturnData(extractOpReturnData[i].input);
      const res = await instance.extractOpReturnData.call(extractOpReturnData[i].input);
      assert.strictEqual(res, extractOpReturnData[i].output);
    }

    for (let i = 0; i < extractOpReturnDataError.length; i += 1) {
      try {
        const res = await instance.extractOpReturnData.call(extractOpReturnDataError[i].input);
        assert(!(extractOpReturnDataError[i].solidityError), 'expected an error message');
        assert.isNull(res);
      } catch (e) {
        assert.include(e.message, extractOpReturnDataError[i].solidityError);
      }
    }
  });

  it('extracts inputs at specified indices', async () => {
    for (let i = 0; i < extractInputAtIndex.length; i += 1) {
      await instance.extractInputAtIndex(
        extractInputAtIndex[i].input.vin,
        extractInputAtIndex[i].input.index
      );
      const res = await instance.extractInputAtIndex.call(
        extractInputAtIndex[i].input.vin,
        extractInputAtIndex[i].input.index
      );
      assert.strictEqual(res, extractInputAtIndex[i].output);
    }
  });

  it('extract input errors on bad vin', async () => {
    for (let i = 0; i < extractInputAtIndexError.length; i += 1) {
      try {
        await instance.extractInputAtIndex(
          extractInputAtIndexError[i].input.vin,
          extractInputAtIndexError[i].input.index
        );
        assert(false, 'expected an error');
      } catch (e) {
        assert.include(e.message, extractInputAtIndexError[i].solidityError, `${extractInputAtIndexError[i].input.vin} ${extractInputAtIndexError[i].input.index}`);
      }
    }
  });

  it('sorts legacy from witness inputs', async () => {
    for (let i = 0; i < isLegacyInput.length; i += 1) {
      await instance.isLegacyInput(isLegacyInput[i].input);
      const res = await instance.isLegacyInput.call(isLegacyInput[i].input);
      assert.strictEqual(res, isLegacyInput[i].output);
    }
  });

  it('extracts the scriptSig from inputs', async () => {
    for (let i = 0; i < extractScriptSig.length; i += 1) {
      await instance.extractScriptSig(extractScriptSig[i].input);
      const res = await instance.extractScriptSig.call(extractScriptSig[i].input);
      assert.strictEqual(res, extractScriptSig[i].output);
    }
  });

  it('errors on bad varints in extractScriptSig', async () => {
    for (let i = 0; i < extractScriptSigError.length; i += 1) {
      try {
        await instance.extractScriptSig(
          extractScriptSigError[i].input
        );
        assert(false, 'expected an error');
      } catch (e) {
        assert.include(e.message, extractScriptSigError[i].solidityError);
      }
    }
  });

  it('extracts the length of the VarInt and scriptSig from inputs', async () => {
    for (let i = 0; i < extractScriptSigLen.length; i += 1) {
      await instance.extractScriptSigLen(extractScriptSigLen[i].input);
      const res = await instance.extractScriptSigLen.call(extractScriptSigLen[i].input);
      assert(res[0].eq(new BN(extractScriptSigLen[i].output[0], 10)));
      assert(res[1].eq(new BN(extractScriptSigLen[i].output[1], 10)));
    }
  });

  it('validates vin length based on stated size', async () => {
    for (let i = 0; i < validateVin.length; i += 1) {
      await instance.validateVin(validateVin[i].input);
      const res = await instance.validateVin.call(validateVin[i].input);
      assert.strictEqual(res, validateVin[i].output);
    }
  });

  it('validates vout length based on stated size', async () => {
    for (let i = 0; i < validateVout.length; i += 1) {
      if (validateVout[i].solidityError) {
        try {
          await instance.validateVout(validateVout[i].input);
          assert(false, 'expected an error');
        } catch (e) {
          assert.include(e.message, validateVout[i].solidityError);
        }
      } else {
        await instance.validateVout(validateVout[i].input);
        const res = await instance.validateVout.call(validateVout[i].input);
        assert.strictEqual(res, validateVout[i].output);
      }
    }
  });

  it('determines output length properly', async () => {
    for (let i = 0; i < determineOutputLength.length; i += 1) {
      await instance.determineOutputLength(determineOutputLength[i].input);
      const res = await instance.determineOutputLength.call(determineOutputLength[i].input);
      const expected = new BN(determineOutputLength[i].output, 10);
      assert(
        res.eq(expected),
        `Output Length Test Failed: expected ${expected.toString()}, got ${res.toString()}`
      );
    }
  });

  it('extracts outputs at specified indices', async () => {
    for (let i = 0; i < extractOutputAtIndex.length; i += 1) {
      await instance.extractOutputAtIndex(
        extractOutputAtIndex[i].input.vout,
        extractOutputAtIndex[i].input.index
      );
      const res = await instance.extractOutputAtIndex.call(
        extractOutputAtIndex[i].input.vout,
        extractOutputAtIndex[i].input.index
      );
      assert.strictEqual(res, extractOutputAtIndex[i].output);
    }
  });

  it('errors while extracting outputs at specified indices', async () => {
    for (let i = 0; i < extractOutputAtIndexError.length; i += 1) {
      try {
        await instance.extractOutputAtIndex(
          extractOutputAtIndexError[i].input.vout,
          extractOutputAtIndexError[i].input.index
        );
      } catch (e) {
        assert.include(e.message, extractOutputAtIndexError[i].solidityError, `${extractOutputAtIndexError[i].input.vout} ${extractOutputAtIndexError[i].input.index}`);
      }
    }
  });

  it('extracts a root from a header', async () => {
    for (let i = 0; i < extractMerkleRootLE.length; i += 1) {
      await instance.extractMerkleRootLE(extractMerkleRootLE[i].input);
      const res = await instance.extractMerkleRootLE.call(extractMerkleRootLE[i].input);
      assert.strictEqual(res, extractMerkleRootLE[i].output);
    }
  });

  it('extracts the target from a header', async () => {
    for (let i = 0; i < extractTarget.length; i += 1) {
      await instance.extractTarget(extractTarget[i].input);
      const res = await instance.extractTarget.call(extractTarget[i].input);
      assert(res.eq(new BN(extractTarget[i].output.slice(2), 16)));
    }
  });

  it('extracts the prev block hash', async () => {
    for (let i = 0; i < extractPrevBlockLE.length; i += 1) {
      await instance.extractPrevBlockLE(extractPrevBlockLE[i].input);
      const res = await instance.extractPrevBlockLE.call(extractPrevBlockLE[i].input);
      assert.strictEqual(res, extractPrevBlockLE[i].output);
    }
  });

  it('extracts a timestamp from a header', async () => {
    for (let i = 0; i < extractTimestamp.length; i += 1) {
      await instance.extractTimestamp(extractTimestamp[i].input);
      const res = await instance.extractTimestamp.call(extractTimestamp[i].input);
      assert.equal(
        res.toNumber(),
        extractTimestamp[i].output
      );
    }
  });

  it('verifies a bitcoin merkle root', async () => {
    for (let i = 0; i < verifyHash256Merkle.length; i += 1) {
      await instance.verifyHash256Merkle(
        verifyHash256Merkle[i].input.proof,
        verifyHash256Merkle[i].input.index
      ); // 0-indexed
      const res = await instance.verifyHash256Merkle.call(
        verifyHash256Merkle[i].input.proof,
        verifyHash256Merkle[i].input.index
      ); // 0-indexed
      assert.strictEqual(res, verifyHash256Merkle[i].output);
    }
  });

  it('determines VarInt data lengths correctly', async () => {
    for (let i = 0; i < determineVarIntDataLength.length; i += 1) {
      await instance.determineVarIntDataLength(`0x${(determineVarIntDataLength[i].input).toString(16)}`);
      const res = await instance.determineVarIntDataLength.call(`0x${(determineVarIntDataLength[i].input).toString(16)}`);
      assert(res.eq(new BN(determineVarIntDataLength[i].output, 10)));
    }
  });

  it('parses VarInts', async () => {
    for (let i = 0; i < parseVarInt.length; i += 1) {
      await instance.parseVarInt(parseVarInt[i].input);
      const res = await instance.parseVarInt.call(parseVarInt[i].input);
      assert(res[0].eq(new BN(parseVarInt[i].output[0], 10)));
      assert(res[1].eq(new BN(parseVarInt[i].output[1], 10)));
    }
  });

  it('returns error for invalid VarInts', async () => {
    for (let i = 0; i < parseVarIntError.length; i += 1) {
      await instance.parseVarInt(parseVarIntError[i].input);
      const res = await instance.parseVarInt.call(parseVarIntError[i].input);
      assert(res[0].eq(new BN('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)), 'did not get error code');
      assert(res[1].eq(new BN(0, 10)), `got non-0 value: ${res[1].toString()}`);
    }
  });

  it('calculates consensus-correct retargets', async () => {
    let firstTimestamp;
    let secondTimestamp;
    let previousTarget;
    let expectedNewTarget;
    let res;
    for (let i = 0; i < retargetAlgorithm.length; i += 1) {
      firstTimestamp = retargetAlgorithm[i].input[0].timestamp;
      secondTimestamp = retargetAlgorithm[i].input[1].timestamp;
      previousTarget = await instance.extractTarget.call(retargetAlgorithm[i].input[1].hex);
      expectedNewTarget = await instance.extractTarget.call(retargetAlgorithm[i].input[2].hex);
      await instance.retargetAlgorithm(previousTarget, firstTimestamp, secondTimestamp);
      res = await instance.retargetAlgorithm.call(previousTarget, firstTimestamp, secondTimestamp);
      // (response & expected) == expected
      // this converts our full-length target into truncated block target
      assert(res.uand(expectedNewTarget).eq(expectedNewTarget));

      secondTimestamp = firstTimestamp + 5 * 2016 * 10 * 60; // longer than 4x
      await instance.retargetAlgorithm(previousTarget, firstTimestamp, secondTimestamp);
      res = await instance.retargetAlgorithm.call(previousTarget, firstTimestamp, secondTimestamp);
      assert(res.divn(4).uand(previousTarget).eq(previousTarget));

      secondTimestamp = firstTimestamp + 2016 * 10 * 14; // shorter than 1/4x
      await instance.retargetAlgorithm(previousTarget, firstTimestamp, secondTimestamp);
      res = await instance.retargetAlgorithm.call(previousTarget, firstTimestamp, secondTimestamp);
      assert(res.muln(4).uand(previousTarget).eq(previousTarget));
    }
  });

  it('extracts difficulty from a header', async () => {
    let actual;
    let expected;
    for (let i = 0; i < retargetAlgorithm.length; i += 1) {
      await instance.extractDifficulty(retargetAlgorithm[i].input[0].hex);
      actual = await instance.extractDifficulty.call(retargetAlgorithm[i].input[0].hex);
      expected = new BN(retargetAlgorithm[i].input[0].difficulty, 10);
      assert(actual.eq(expected));

      await instance.extractDifficulty(retargetAlgorithm[i].input[1].hex);
      actual = await instance.extractDifficulty.call(retargetAlgorithm[i].input[1].hex);
      expected = new BN(retargetAlgorithm[i].input[1].difficulty, 10);
      assert(actual.eq(expected));

      await instance.extractDifficulty(retargetAlgorithm[i].input[2].hex);
      actual = await instance.extractDifficulty.call(retargetAlgorithm[i].input[2].hex);
      expected = new BN(retargetAlgorithm[i].input[2].difficulty, 10);
      assert(actual.eq(expected));
    }
  });
});
