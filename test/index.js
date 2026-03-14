'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const sinon = require('sinon')

const Address = require('address-rfc2821')
const fixtures = require('haraka-test-fixtures')

beforeEach(function () {
  this.plugin = new fixtures.plugin('bounce')

  // replace vm-compiled functions with instrumented versions for coverage tracking
  if (process.env.HARAKA_COVERAGE) {
    const plugin_module = require('../index.js')
    Object.assign(this.plugin, plugin_module)
  }

  this.connection = fixtures.connection.createConnection()
  this.connection.remote.ip = '8.8.8.8'
  this.connection.relaying = false
  this.connection.init_transaction()
  this.connection.transaction.mail_from = new Address.Address('<>')
  this.connection.transaction.rcpt_to.push(new Address.Address('test@example.com'))

  this.plugin.register()

  this.should_skip_spy = sinon.spy(this.plugin, 'should_skip')
})

afterEach(sinon.restore)

describe('register', function () {
  it('should have register function', function () {
    const load_bounce_ini_spy = sinon.spy(this.plugin, 'load_bounce_ini')
    const load_bounce_bad_rcpt_spy = sinon.spy(this.plugin, 'load_bounce_bad_rcpt')
    const load_bounce_whitelist_spy = sinon.spy(this.plugin, 'load_bounce_whitelist')
    const validate_config_spy = sinon.spy(this.plugin, 'validate_config')

    assert.strictEqual('function', typeof this.plugin.register)

    this.plugin.register()

    assert.ok(load_bounce_ini_spy.calledOnce)
    assert.ok(load_bounce_bad_rcpt_spy.calledOnce)
    assert.ok(load_bounce_whitelist_spy.calledOnce)
    assert.ok(validate_config_spy.calledOnce)
  })

  it('registers hooks', function () {
    assert.ok(this.plugin.register_hook.called)
    let hook_count = 0
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'check_null_sender')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'reject_all')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'bad_rcpt')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'single_recipient')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'bounce_spf_enable')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'empty_return_path')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'create_validation_hash')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'validate_bounce')
    assert.strictEqual(this.plugin.register_hook.args[hook_count++][1], 'bounce_spf')
    assert.strictEqual(this.plugin.register_hook.args.length, hook_count)
  })
})

describe('load_configs', function () {
  it('load_bounce_ini', function () {
    this.plugin.load_bounce_ini()

    assert.ok(this.plugin.cfg.check)
    assert.ok(this.plugin.cfg.reject)
    assert.strictEqual(this.plugin.cfg.validation.max_hash_age_days, 6)
    assert.strictEqual(this.plugin.cfg.validation.hash_algorithm, 'sha256')
    assert.ok(this.plugin.cfg.skip)
  })

  it('load_bounce_bad_rcpt', function () {
    const config_get_stub = sinon.stub(this.plugin.config, 'get')
    config_get_stub.returns(['Test1@Example.com', 'TEST2@example.COM'])

    this.plugin.load_bounce_bad_rcpt()

    assert.ok(config_get_stub.calledWith('bounce_bad_rcpt', 'list'))
    // Verify addresses are lowercased
    assert.deepEqual(this.plugin.cfg.invalid_addrs, ['test1@example.com', 'test2@example.com'])
  })

  it('load_bounce_whitelist', function () {
    const config_get_stub = sinon.stub(this.plugin.config, 'get')
    // Stub config.get() to return whitelist with mixed-case keys and values
    config_get_stub.returns({
      'Test@Example.com': ['No-Reply@Example.com', 'Support@Example.COM'],
      'FOO@Example.com': ['*@Example.NET', 'Sales@example.com'],
    })

    this.plugin.load_bounce_whitelist()

    assert.ok(config_get_stub.calledWith('bounce_whitelist.json'))

    // Verify all keys and values are lowercased
    assert.deepEqual(this.plugin.cfg.whitelist['test@example.com'], ['no-reply@example.com', 'support@example.com'])
    assert.deepEqual(this.plugin.cfg.whitelist['foo@example.com'], ['*@example.net', 'sales@example.com'])
    assert.strictEqual(Object.keys(this.plugin.cfg.whitelist).length, 2)
  })
})

describe('validate_config', function () {
  let getHashes_stub, logerror_spy

  beforeEach(function () {
    this.plugin.cfg = {
      check: {
        single_recipient: true,
        empty_return_path: false,
        bounce_spf: true,
        hash_validation: true,
      },
      reject: {
        single_recipient: true,
        empty_return_path: false,
        bounce_spf: false,
        hash_validation: false,
      },
      validation: {
        max_hash_age_days: 6,
        hash_algorithm: 'sha256',
      },
    }

    logerror_spy = sinon.spy(this.plugin, 'logerror')
    getHashes_stub = sinon.stub(crypto, 'getHashes')
    getHashes_stub.returns(['sha256', 'sha512', 'md5'])
  })

  it('will set default max hash age', function () {
    delete this.plugin.cfg.validation.max_hash_age_days

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.strictEqual(this.plugin.cfg.validation.max_hash_age_days, 6)
  })

  it('will enable single recipient check', function () {
    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(this.plugin.cfg.check.single_recipient)
  })

  it('will enable empty return path check', function () {
    this.plugin.cfg.reject.empty_return_path = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(this.plugin.cfg.check.empty_return_path)
  })

  it('will enable bounce SPF check', function () {
    this.plugin.cfg.reject.bounce_spf = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(this.plugin.cfg.check.bounce_spf)
  })

  it('will enable bounce hash validation', function () {
    this.plugin.cfg.reject.hash_validation = true
    this.plugin.cfg.validation.secret = crypto.randomBytes(32).toString('base64')

    this.plugin.validate_config()

    assert.ok(this.plugin.cfg.check.hash_validation)
    assert.ok(getHashes_stub.calledOnce)
  })

  it('will not check hash validation', function () {
    this.plugin.cfg.check.hash_validation = false

    this.plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.strictEqual(this.plugin.cfg.check.hash_validation, false)
  })

  it('has invalid hash algorithm', function () {
    this.plugin.cfg.validation.hash_algorithm = 'invalid_algorithm'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.strictEqual(this.plugin.cfg.check.hash_validation, false)
  })

  it('is missing hash algorithm', function () {
    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.strictEqual(this.plugin.cfg.validation.hash_algorithm, 'sha256')
  })

  it('is missing the secret key', function () {
    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.strictEqual(this.plugin.cfg.check.hash_validation, false)
  })

  it('has short secret key', function () {
    this.plugin.cfg.validation.secret = 'short_key'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_spy.calledOnce)
    assert.strictEqual(this.plugin.cfg.check.hash_validation, false)
  })

  it('has default secret', function () {
    this.plugin.cfg.validation.secret = 'your_generated_secret_here'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_spy.calledOnce)
    assert.strictEqual(this.plugin.cfg.check.hash_validation, false)
  })

  it('has valid secret', function () {
    this.plugin.cfg.validation.secret = 'valid_secret_thats_at_least_32_characters_long'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_spy.notCalled)
  })
})

describe('reject_all', function () {
  beforeEach(function () {
    this.plugin.cfg.reject.all_bounces = true
  })

  it('will allow bounces', async function () {
    this.plugin.cfg.reject.all_bounces = false
    await new Promise((resolve) => {
      this.plugin.reject_all((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('reject_all - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.reject_all((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will ignore outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.reject_all((code, msg) => {
        assert.ok(this.should_skip_spy.returned(true))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will ignore non-bounce mail', async function () {
    this.connection.transaction.results.add(this.plugin, { isa: 'no' })
    this.connection.transaction.mail_from = new Address.Address('<test@example.com>')
    await new Promise((resolve) => {
      this.plugin.reject_all((code, msg) => {
        assert.ok(this.should_skip_spy.returned(true))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will reject all bounces', async function () {
    await new Promise((resolve) => {
      this.connection.transaction.results.add(this.plugin, { isa: 'yes' })
      this.plugin.reject_all((code, msg) => {
        assert.ok(this.should_skip_spy.returned(false))
        this.connection.transaction.results.has(this.plugin, 'fail', 'bounces_accepted')
        this.connection.transaction.results.has(this.plugin, 'msg', 'bounces not accepted here')
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'Bounces not accepted here')
        resolve()
      }, this.connection)
    })
  })
})

describe('empty_return_path', function () {
  beforeEach(function () {
    this.plugin.cfg.check.empty_return_path = true
    this.plugin.cfg.reject.empty_return_path = true
  })

  it('empty_return_path - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('should ignore empty_return_path', async function () {
    this.plugin.cfg.check.empty_return_path = false

    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will ignore outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.returned(true))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has missing Return-Path header', async function () {
    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.returned(false))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'empty_return_path'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has empty Return-Path header', async function () {
    this.connection.transaction.add_header('Return-Path', '')
    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.returned(false))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'empty_return_path'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has empty return path in Return-Path header', async function () {
    this.connection.transaction.add_header('Return-Path', '<>')
    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.returned(false))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'empty_return_path'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will allow non-empty Return-Path header', async function () {
    this.connection.transaction.add_header('Return-Path', 'Hello World!')

    this.plugin.cfg.reject.empty_return_path = false

    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.returned(false))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'empty_return_path'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'bounce with non-empty Return-Path'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will reject non-empty Return-Path header', async function () {
    this.connection.transaction.add_header('Return-Path', 'Hello World!')

    await new Promise((resolve) => {
      this.plugin.empty_return_path((code, msg) => {
        assert.ok(this.should_skip_spy.returned(false))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'empty_return_path'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'bounce with non-empty Return-Path'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'bounce with non-empty Return-Path (RFC 3834)')
        resolve()
      }, this.connection)
    })
  })
})

describe('single_recipient', function () {
  it('single_recipient - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.single_recipient((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will not check for single recipient', async function () {
    this.plugin.cfg.check.single_recipient = false
    await new Promise((resolve) => {
      this.plugin.single_recipient((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will ignore outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.single_recipient((code, msg) => {
        assert.ok(this.should_skip_spy.returned(true))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has single recipient', async function () {
    await new Promise((resolve) => {
      this.plugin.single_recipient((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'single_recipient'))
        assert.ok(this.should_skip_spy.calledOnce)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will allow multiple recipients', async function () {
    this.plugin.cfg.reject.single_recipient = false
    this.connection.transaction.rcpt_to.push(new Address.Address('test2@example.com'))
    await new Promise((resolve) => {
      this.plugin.single_recipient((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'single_recipient'))
        assert.ok(this.should_skip_spy.calledOnce)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will reject multiple recipients', async function () {
    this.connection.transaction.rcpt_to.push(new Address.Address('test2@example.com'))
    await new Promise((resolve) => {
      this.plugin.single_recipient((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'single_recipient'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'too many recipients'))
        assert.ok(this.should_skip_spy.calledOnce)
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'this bounce message has too many recipients')
        resolve()
      }, this.connection)
    })
  })
})

describe('bad_rcpt', function () {
  beforeEach(function () {
    const raw_list = ['bad1@example.com', 'BAD2@example.com']
    this.plugin.cfg.invalid_addrs = raw_list.map((n) => n.toLowerCase())
  })

  it('will not check for bad recipient', async function () {
    this.plugin.cfg.reject.bad_rcpt = false

    await new Promise((resolve) => {
      this.plugin.bad_rcpt(
        (code, msg) => {
          assert.ok(this.should_skip_spy.notCalled)
          assert.strictEqual(code, undefined)
          assert.strictEqual(msg, undefined)
          resolve()
        },
        this.connection,
        [new Address.Address('<>')],
      )
    })
  })

  it('bad_rcpt - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.bad_rcpt((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will ignore outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.bad_rcpt((code, msg) => {
        assert.ok(this.should_skip_spy.returned(true))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will verify recipient allows bounces', function () {
    this.plugin.cfg.invalid_addrs = []
    const rcpt = new Address.Address('test@example.com')
    this.plugin.bad_rcpt(
      (code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'bad_rcpt'))
        assert.ok(this.should_skip_spy.calledOnce)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
      },
      this.connection,
      rcpt,
    )
  })

  it('will check for invalid recipient', async function () {
    const rcpt = new Address.Address('bad1@example.com')
    await new Promise((resolve) => {
      this.plugin.bad_rcpt(
        (code, msg) => {
          assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bad_rcpt'))
          assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'rcpt does not accept bounces'))
          assert.ok(this.should_skip_spy.calledOnce)
          assert.strictEqual(code, DENY)
          assert.strictEqual(msg, `${rcpt.address()} does not accept bounces`)
          resolve()
        },
        this.connection,
        rcpt,
      )
    })
  })
})

describe('bounce_spf_enable', function () {
  it('bounce_spf_enable - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.bounce_spf_enable((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.bounce_spf_enable((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        assert.strictEqual(this.connection.transaction.parse_body, false)
        resolve()
      }, this.connection)
    })
  })

  it('is inbound mail', async function () {
    this.connection.relaying = false
    this.connection.transaction.results.add(this.plugin, { isa: 'yes' })

    await new Promise((resolve) => {
      this.plugin.bounce_spf_enable((code, msg) => {
        assert.ok(this.should_skip_spy.calledOnce)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        assert.strictEqual(this.connection.transaction.parse_body, true)
        resolve()
      }, this.connection)
    })
  })
})

describe('bounce_spf', function () {
  const { SPF } = require('haraka-plugin-spf')

  let spf_check_host_stub, find_received_headers_stub
  let spf

  beforeEach(function () {
    this.connection.transaction.body = {
      bodytext: `Received: from example.com (example.com [96.7.128.198])`,
      children: [],
    }
    this.connection.transaction.parse_body = true
    this.connection.transaction.mail_from = new Address.Address('<>')
    this.connection.transaction.results.add(this.plugin, { isa: 'yes' })

    this.plugin.cfg.reject.bounce_spf = true

    spf_check_host_stub = sinon.stub(SPF.prototype, 'check_host')
    find_received_headers_stub = sinon.stub(this.plugin, 'find_received_headers')

    spf = new SPF()
  })

  it('bounce_spf - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('skip SPF check', async function () {
    this.plugin.cfg.check.bounce_spf = false

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will skip outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(this.should_skip_spy.calledOnce)
        assert.ok(find_received_headers_stub.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will skip when not a null sender', async function () {
    this.connection.transaction.results.add(this.plugin, { isa: 'no' })
    this.connection.transaction.mail_from = new Address.Address('<test@example.com>')

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(this.should_skip_spy.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'no'))
        assert.ok(find_received_headers_stub.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will skip when hash validation passed', async function () {
    this.connection.transaction.results.add(this.plugin, {
      pass: 'validate_bounce',
    })

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(this.should_skip_spy.calledOnce)
        assert.ok(find_received_headers_stub.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has no IPs', async function () {
    this.connection.transaction.body.bodytext = ''

    find_received_headers_stub.returns(new Set())
    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'yes'))
        assert(find_received_headers_stub.calledOnce)
        assert(find_received_headers_stub.calledWith(this.connection.transaction.body))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'no IP addresses found in message'))
        assert.ok(spf_check_host_stub.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has multiple IPs - 1st IP fails, 2nd IP passes', async function () {
    this.connection.transaction.body.bodytext = 'filler'

    find_received_headers_stub.returns(new Set(['1.2.3.4', '5.6.7.8']))
    spf_check_host_stub.onFirstCall().resolves(spf.SPF_FAIL)
    spf_check_host_stub.onSecondCall().resolves(spf.SPF_PASS)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert(find_received_headers_stub.calledOnce)
        assert(find_received_headers_stub.calledWith(this.connection.transaction.body))
        assert.ok(spf_check_host_stub.calledTwice)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'yes'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'bounce_spf'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('SPF_TEMPERROR', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_TEMPERROR)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'SPF returned TempError'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('SPF_PERMERROR', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_PERMERROR)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'SPF returned PermError'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('SPF_NONE', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_NONE)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'SPF returned None'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('SPF_PASS', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_PASS)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'bounce_spf'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('SPF_NEUTRAL', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_NEUTRAL)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'Invalid bounce (spoofed sender)')
        resolve()
      }, this.connection)
    })
  })

  it('SPF_SOFTFAIL', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_SOFTFAIL)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'Invalid bounce (spoofed sender)')
        resolve()
      }, this.connection)
    })
  })

  it('skip SPF reject', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_FAIL)

    this.plugin.cfg.reject.bounce_spf = false

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('SPF_FAIL', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    spf_check_host_stub.resolves(spf.SPF_FAIL)

    await new Promise((resolve) => {
      this.plugin.bounce_spf((code, msg) => {
        assert.ok(spf_check_host_stub.calledOnce)
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_spf'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'Invalid bounce (spoofed sender)')
        resolve()
      }, this.connection)
    })
  })
})

describe('create_validation_hash', function () {
  let get_decoded_spy

  beforeEach(function () {
    this.connection.transaction.body = {
      bodytext: '',
      children: [],
    }
    this.connection.transaction.parse_body = true
    this.connection.transaction.mail_from = new Address.Address('<test@example.com>')
    this.connection.relaying = true
    this.plugin.cfg.check.hash_validation = true

    get_decoded_spy = sinon.spy(this.connection.transaction.header, 'get_decoded')
  })

  it('create_validation_hash - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('should not create validation hash', async function () {
    this.plugin.cfg.check.hash_validation = false

    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        sinon.assert.notCalled(get_decoded_spy)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('should ignore inbound mail', async function () {
    this.connection.relaying = false

    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        sinon.assert.notCalled(get_decoded_spy)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('should skip outbound with null sender', async function () {
    this.connection.transaction.mail_from = new Address.Address('<>')
    this.connection.relaying = true
    this.connection.transaction.results.add(this.plugin, { isa: 'yes' })

    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        sinon.assert.notCalled(get_decoded_spy)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('missing Message-ID header', async function () {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'

    this.connection.transaction.add_header('From', from_header)
    this.connection.transaction.add_header('Date', date_header)

    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        sinon.assert.calledThrice(get_decoded_spy)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('missing From, Date, and Message-ID headers', async function () {
    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        sinon.assert.calledThrice(get_decoded_spy)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('should create a validation hash', async function () {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'
    const message_id = '<test@example.COM>'

    this.plugin.cfg.validation.secret = crypto.randomBytes(32).toString('base64')

    this.connection.transaction.add_header('From', from_header)
    this.connection.transaction.add_header('Date', date_header)
    this.connection.transaction.add_header('Message-ID', message_id)

    await new Promise((resolve) => {
      this.plugin.create_validation_hash((code, msg) => {
        sinon.assert.calledThrice(get_decoded_spy)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })
})

describe('validate_bounce', function () {
  let find_bounce_headers_stub
  let hash, amalgam
  let date_header, from_header, message_id

  beforeEach(function () {
    this.plugin.cfg.check.hash_validation = true
    this.plugin.cfg.reject.hash_validation = true
    this.plugin.cfg.validation.secret = crypto.randomBytes(32).toString('base64')

    this.plugin.cfg.whitelist = {}

    this.connection.transaction.body = {
      bodytext: '',
      children: [],
    }

    date_header = new Date().toISOString()
    from_header = '<test@example.com>'
    message_id = '<test@example.com>'

    amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(this.plugin.cfg.validation.hash_algorithm, this.plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')

    find_bounce_headers_stub = sinon.stub(this.plugin, 'find_bounce_headers')
  })

  it('validate_bounce - missing transaction', async function () {
    delete this.connection.transaction

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('should skip validation check', async function () {
    this.plugin.cfg.check.hash_validation = false

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will ignore outbound mail', async function () {
    this.connection.relaying = true

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.should_skip_spy.returned(true))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has hash size that is too short', async function () {
    hash = '1234567890'

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    this.plugin.cfg.reject.hash_validation = false

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'hash length mismatch'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(this.connection.transaction.body))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has hash size that is too long', async function () {
    this.plugin.cfg.reject.hash_validation = false

    const hash = '1234567890123456789012345678901234567890123456789012345678901234567890'

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'hash length mismatch'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will reject if wrong hash size', async function () {
    const hash = '1234567890'

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'hash length mismatch'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('is a valid inbound bounce', async function () {
    const headers = create_headers(this.plugin)
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'validate_bounce'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(this.connection.transaction.body))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is a valid inbound bounce and will skip data_post in remaining plugins', async function () {
    const headers = create_headers(this.plugin)
    find_bounce_headers_stub.returns(headers)
    this.plugin.cfg.skip.remaining_plugins = true

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'pass', 'validate_bounce'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(this.connection.transaction.body))
        assert.strictEqual(code, OK)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('has incorrect hash', async function () {
    this.plugin.cfg.reject.hash_validation = false

    hash = crypto
      .createHmac(this.plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'hash does not match'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will deny when incorrect hash', async function () {
    hash = crypto
      .createHmac(this.plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'hash does not match'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('is missing the From header', async function () {
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.from
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing headers'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is missing the Date header', async function () {
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.date
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing headers'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is missing the Message-ID header', async function () {
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.message_id
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing headers'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will deny when missing the From header', async function () {
    const headers = create_headers(this.plugin)
    delete headers.from
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing headers'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('will deny when missing the Date header', async function () {
    const headers = create_headers(this.plugin)
    delete headers.date
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing headers'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('will deny when missing the Message-ID header', async function () {
    const headers = create_headers(this.plugin)
    delete headers.message_id
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing headers'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('is missing hash header and address parsing fails', async function () {
    const from = 'evil-mailer'
    const rcpt = new Address.Address('test@example.com')

    this.plugin.cfg.reject.hash_validation = false
    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid from header'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is missing hash header and email address is whitelisted', async function () {
    this.plugin.cfg.whitelist = { 'test@example.com': ['no-reply@example.com'] }

    const from = '<no-reply@example.com>'
    const rcpt = new Address.Address('test@example.com')

    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'whitelisted'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is missing hash header and sender domain is whitelisted', async function () {
    this.plugin.cfg.whitelist = { 'test@example.com': ['*@example.net'] }

    const from = '<info@example.net>'
    const rcpt = new Address.Address('test@example.com')

    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'whitelisted'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('is missing hash header and has invalid from header', async function () {
    const from = '<invalid>'
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid from header'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)

        resolve()
      }, this.connection)
    })
  })

  it('is missing hash header', async function () {
    const from = '<info@example.net>'
    this.connection.transaction.add_header('From', from)
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing validation hash'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will deny when missing hash header', async function () {
    const from = '<info@example.net>'
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing validation hash'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('is missing all headers', async function () {
    const headers = {}
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'skip', 'validate_bounce'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'missing all headers'))
        assert.strictEqual(code, undefined)
        assert.strictEqual(msg, undefined)
        resolve()
      }, this.connection)
    })
  })

  it('will Deny when hash is too old', async function () {
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_date'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'hash is too old'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(this.connection.transaction.body))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('has invalid date header', async function () {
    date_header = 'invalid date'

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_date'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid date header'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })

  it('will DENY when date header is invalid', async function () {
    date_header = 'invalid date'

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      this.plugin.validate_bounce((code, msg) => {
        assert.ok(this.connection.transaction.results.has(this.plugin, 'fail', 'bounce_date'))
        assert.ok(this.connection.transaction.results.has(this.plugin, 'msg', 'invalid date header'))
        assert.strictEqual(code, DENY)
        assert.strictEqual(msg, 'invalid bounce')
        resolve()
      }, this.connection)
    })
  })
})

describe('is_date_valid', function () {
  it('has recent date', function () {
    const oneDayAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 1)
    const date_header = oneDayAgo.toUTCString()

    const result = this.plugin.is_date_valid(date_header)
    assert(result.valid)
  })

  it('has expired date', function () {
    const SevenDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 7)
    const date_header = SevenDaysAgo.toUTCString()
    const result = this.plugin.is_date_valid(date_header)
    assert.strictEqual(result.valid, false)
    assert.strictEqual(result.msg, 'hash is too old')
  })

  it('has invalid date', function () {
    const not_a_date = 'hello world'
    const result = this.plugin.is_date_valid(not_a_date)
    assert.strictEqual(result.valid, false)
    assert.strictEqual(result.msg, 'invalid date header')
  })
})

describe('is_whitelisted', function () {
  it('is not whitelisted', function () {
    this.plugin.cfg.whitelist = {}

    const whitelisted = this.plugin.is_whitelisted('test@example.com', 'support@example.com')

    assert.strictEqual(whitelisted, false)
  })

  it('is whitelisted with an exact match', function () {
    this.plugin.cfg.whitelist = { 'test@example.com': ['support@example.com'] }

    const whitelisted = this.plugin.is_whitelisted('test@example.com', 'support@example.com')

    assert.ok(whitelisted)
  })

  it('is whitelisted with a wildcard match', function () {
    this.plugin.cfg.whitelist = {
      'test@example.com': ['support@example.net', '*@example.com'],
    }

    const whitelisted = this.plugin.is_whitelisted('test@example.com', 'support@example.com')

    assert.ok(whitelisted)
  })
})

describe('find_bounce_headers', function () {
  let date, from, message_id, hash
  let msg_body, transaction

  beforeEach(function () {
    ;({ from, date, message_id, hash } = create_headers(this.plugin))

    msg_body = `
X-Haraka-Bounce-Validation: ${hash}
From: ${from}
Date: ${date}
Message-ID: ${message_id}
`
    transaction = this.connection.transaction

    transaction.body = {
      bodytext: msg_body,
      children: [],
    }
  })

  it('has no body', function () {
    delete transaction.body

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(JSON.stringify(headers), '{}')
  })

  it('has all headers in body', function () {
    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, from)
    assert.strictEqual(headers.date, date)
    assert.strictEqual(headers.message_id, message_id)
    assert.strictEqual(headers.hash, hash)
  })

  it('has From header in body', function () {
    transaction.body.bodytext = `From: ${from}
Content-Type: text/plain`

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, from)
    assert.strictEqual(headers.date, undefined)
    assert.strictEqual(headers.message_id, undefined)
    assert.strictEqual(headers.hash, undefined)
  })

  it('has Date header in body', function () {
    transaction.body.bodytext = `Date: ${date}\n`

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, undefined)
    assert.strictEqual(headers.date, date)
    assert.strictEqual(headers.message_id, undefined)
    assert.strictEqual(headers.hash, undefined)
  })

  it('has no headers in body', function () {
    transaction.body.bodytext = 'no headers in this body'

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, undefined)
    assert.strictEqual(headers.date, undefined)
    assert.strictEqual(headers.message_id, undefined)
    assert.strictEqual(headers.hash, undefined)
  })

  it('has headers in body.children', function () {
    transaction.body = {
      bodytext: 'Hello World',
      children: [{ bodytext: msg_body }],
    }

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, from)
    assert.strictEqual(headers.date, date)
    assert.strictEqual(headers.message_id, message_id)
    assert.strictEqual(headers.hash, hash)
  })

  it('has no headers in body.children', function () {
    transaction.body = {
      bodytext: 'Hello World',
      children: [{ bodytext: 'no headers in this body' }],
    }

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, undefined)
    assert.strictEqual(headers.date, undefined)
    assert.strictEqual(headers.message_id, undefined)
    assert.strictEqual(headers.hash, undefined)
  })

  it('has folded headers', function () {
    const unfolded_from = `"Dr. Smith - Dr. Smith's Snake Oil Emporium" <dr.smith@example.com>`
    const folded_from = `"Dr. Smith - Dr. Smith's Snake Oil Emporium"\n  <dr.smith@example.com>`
    transaction.body.bodytext = `
Message-ID: ${message_id}
Date: ${date}
From: ${folded_from}
X-Haraka-Bounce-Validation: ${hash}
`
    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.strictEqual(headers.from, unfolded_from)
    assert.strictEqual(headers.date, date)
    assert.strictEqual(headers.message_id, message_id)
    assert.strictEqual(headers.hash, hash)
  })
})

describe('should_skip', function () {
  it('is relaying and is not a bounce', function () {
    this.connection.transaction.mail_from = new Address.Address('<test@example.com>')
    this.connection.relaying = true
    this.connection.transaction.results.add(this.plugin, { isa: 'no' })

    const result = this.plugin.should_skip(this.connection)

    assert.strictEqual(result, true)
  })

  it('is relaying and is a bounce', function () {
    this.connection.relaying = true
    this.connection.transaction.results.add(this.plugin, { isa: 'yes' })

    const result = this.plugin.should_skip(this.connection)

    assert.strictEqual(result, true)
  })

  it('is not relaying and is not a bounce', function () {
    this.connection.transaction.mail_from = new Address.Address('<test@example.com>')
    this.connection.relaying = false
    this.connection.transaction.results.add(this.plugin, { isa: 'no' })

    const result = this.plugin.should_skip(this.connection)

    assert.strictEqual(result, true)
  })

  it('is not relaying and is a bounce', function () {
    this.connection.relaying = false
    this.connection.transaction.results.add(this.plugin, { isa: 'yes' })

    const result = this.plugin.should_skip(this.connection)

    assert.strictEqual(result, false)
  })
})

describe('find_received_headers', function () {
  beforeEach(function () {
    this.connection.transaction.body = { bodytext: '', children: [] }
  })

  it('has no body', function () {
    const ips = this.plugin.find_received_headers('')

    assert.strictEqual(ips.size, 0)
  })

  it('has no Received headers', function () {
    const ips = this.plugin.find_received_headers(this.connection.transaction.body)

    assert.strictEqual(ips.size, 0)
  })

  it('has one Received header', function () {
    const ip = '209.85.128.52'
    const received_headers = `Received: from example.com (example.com [${ip}])`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(this.connection.transaction.body)

    assert.strictEqual(ips.size, 1)
    assert.ok(ips.has(ip))
  })

  it('has two Received headers with one private IP', function () {
    const ip1 = '10.10.10.10'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (HELO mail.example.com) (${ip2})
`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(this.connection.transaction.body)

    assert.strictEqual(ips.size, 1)
    assert.ok(ips.has(ip2))
  })

  it('has two Received headers with public IPs', function () {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(this.connection.transaction.body)

    assert.strictEqual(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has two Received headers with IPv4 and IPv6 IPs', function () {
    const ip1 = '108.177.12.26'
    const ip2 = '2603:10b6:8:189::16'
    const ip3 = '2603:10b6:303:e9::7'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from prod.example.com
 ([${ip2}]) by prod.example.com (${ip3})
`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(this.connection.transaction.body)

    assert.strictEqual(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has Received headers in child', function () {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`
    this.connection.transaction.body.children[0] = {
      bodytext: received_headers,
      children: [],
    }
    const ips = this.plugin.find_received_headers(this.connection.transaction.body)

    assert.strictEqual(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })
})

describe('extract_header', function () {
  let bodytext, from, date, message_id, hash

  beforeEach(function () {
    ;({ from, date, message_id, hash } = create_headers(this.plugin))

    bodytext = `From: ${from}
Date: ${date}
Message-ID: ${message_id}
X-Haraka-Bounce-Validation: ${hash}
`
  })

  it('should return undefined if bodytext is missing', function () {
    bodytext = null

    const value = this.plugin.extract_header(bodytext, 'From')

    assert.strictEqual(value, undefined)
  })

  it('should return undefined if bodytext is not a string', function () {
    bodytext = {}

    const value = this.plugin.extract_header(bodytext, 'From')

    assert.strictEqual(value, undefined)
  })

  it('should extract the From header', function () {
    const value = this.plugin.extract_header(bodytext, 'From')

    assert.strictEqual(value, from)
  })

  it('should extract the Date header', function () {
    const value = this.plugin.extract_header(bodytext, 'Date')

    assert.strictEqual(value, date)
  })

  it('should extract the Message-ID header', function () {
    const value = this.plugin.extract_header(bodytext, 'Message-ID')

    assert.strictEqual(value, message_id)
  })

  it('should extract the X-Haraka-Bounce-Validation header', function () {
    const value = this.plugin.extract_header(bodytext, 'X-Haraka-Bounce-Validation')

    assert.strictEqual(value, hash)
  })

  it('should extract the folded From header', function () {
    const from_header = `"Dr. Smith - Dr. Smith's Snake Oil Emporium" <dr.smith@example.com>`

    bodytext = `From: "Dr. Smith - Dr. Smith's Snake Oil Emporium"
  <dr.smith@example.com>
Date: ${date}
Message-ID: ${message_id}
X-Haraka-Bounce-Validation: ${hash}
`
    const value = this.plugin.extract_header(bodytext, 'From')

    assert.strictEqual(value, from_header)
  })

  it('should not extract anything', function () {
    const value = this.plugin.extract_header(bodytext, 'In-Reply-To')

    assert.strictEqual(value, undefined)
  })
})

describe('check_null_sender', function () {
  it('is relaying', function () {
    this.connection.relaying = true
    this.plugin.check_null_sender((code, msg) => {
      assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'yes'))
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
    }, this.connection)
  })

  it('has null sender', function () {
    this.plugin.check_null_sender((code, msg) => {
      assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'yes'))
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
    }, this.connection)
  })

  it('has empty string sender', function () {
    this.connection.transaction.mail_from = new Address.Address('')

    this.plugin.check_null_sender((code, msg) => {
      assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'yes'))
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
    }, this.connection)
  })

  it('is not a null sender', function () {
    this.connection.transaction.mail_from = new Address.Address('user@example.com')

    this.plugin.check_null_sender((code, msg) => {
      assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'no'))
      assert.strictEqual(code, undefined)
      assert.strictEqual(msg, undefined)
    }, this.connection)
  })
})

function create_headers(plugin, options = {}) {
  plugin.cfg.validation.secret = crypto.randomBytes(32).toString('base64')

  const date_header = options.date_header || new Date().toISOString()
  const from_header = options.from_header || 'test <test@example.com>'
  const message_id = options.message_id || '<PB8-DCB-KHNZ4Y5J3N0Z@example.com>'

  let hash = options.hash
  if (!hash) {
    const amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')
  }

  return {
    from: from_header,
    date: date_header,
    message_id: message_id,
    hash: hash,
  }
}
