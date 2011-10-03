require 'candlepin_scenarios'

describe 'Consumer Resource' do

  include CandlepinMethods
  include CandlepinScenarios

  before(:each) do
    @owner1 = create_owner random_string('test_owner1')
    @username1 = random_string("user1")
    @consumername1 = random_string("consumer1")
    @user1 = user_client(@owner1, @username1)
    @consumer1 = consumer_client(@user1, @consumername1)

    @owner2 = create_owner random_string('test_owner2')
    @username2 = random_string("user2")
    @user2 = user_client(@owner2, @username2)
    @consumer2 = consumer_client(@user2, random_string("consumer2"))
  end


  it 'allows super admins to see all consumers' do

    uuids = []
    @cp.list_consumers.each do |c|
      # These are HATEOAS serialized consumers, the ID is the numeric DB
      # ID, so pull the UUID off the URL.
      # TODO: Find a better way once client is more HATEOASy.
      uuids << c['href'].split('/')[-1]
    end
    uuids.include?(@consumer1.uuid).should be_true
    uuids.include?(@consumer2.uuid).should be_true
  end

  it 'lets an owner admin see only their consumers' do
    @user2.list_consumers({:owner => @owner2['key']}).length.should == 1
  end

  it 'lets a super admin filter consumers by owner' do
    @cp.list_consumers.size.should > 1
    @cp.list_consumers({:owner => @owner1['key']}).size.should == 1
  end


  it 'lets an owner see only their system consumer types' do
    @user1.list_consumers({:type => 'system', :owner => @owner1['key']}).length.should == 1
  end

  it 'lets a super admin see a peson consumer with a given username' do

    username = random_string("user1")
    user1 = user_client(@owner1, username)
    consumer1 = consumer_client(user1, random_string("consumer1"), 'person')

    @cp.list_consumers({:type => 'person',
                       :username => username}).length.should == 1
  end

  it 'lets a super admin create person consumer for another user' do
    owner1 = create_owner random_string('test_owner1')
    username = random_string "user1"
    user1 = user_client(owner1, username)
    consumer1 = consumer_client(@cp, random_string("consumer1"), 'person',
                                username, {}, owner1['key'])

    @cp.list_consumers({:type => 'person',
        :username => username, :owner => owner1['key']}).length.should == 1
  end

  it 'does not let an owner admin create person consumer for another owner' do
    owner1 = create_owner random_string('test_owner1')
    username = random_string "user1"
    user1 = user_client(owner1, username)

    owner2 = create_owner random_string('test_owner2')
    user2 = user_client(owner2, random_string("user2"))

    lambda do
      consumer_client(user2, random_string("consumer1"), 'person',
                      username)
    end.should raise_exception(RestClient::Forbidden)
  end

  it 'returns a 404 for a non-existant consumer' do
    lambda do
      @cp.get_consumer('fake-uuid')
    end.should raise_exception(RestClient::ResourceNotFound)
  end

  it 'lets a consumer view their own information' do
    owner1 = create_owner random_string('test_owner1')
    user1 = user_client(owner1, random_string("user1"))
    consumer1 = consumer_client(user1, random_string("consumer1"))

    consumer = consumer1.get_consumer(consumer1.uuid)
    consumer['uuid'].should == consumer1.uuid
  end

  it "does not let a consumer view another consumer's information" do
    owner1 = create_owner random_string('test_owner1')
    user1 = user_client(owner1, random_string("user1"))
    consumer1 = consumer_client(user1, random_string("consumer1"))
    consumer2 = consumer_client(user1, random_string("consumer2"))

    lambda do
      consumer1.get_consumer(consumer2.uuid)
    end.should raise_exception(RestClient::Forbidden)
  end

  it "does not let an owner register with UUID of another owner's consumer" do
    linux_net = create_owner 'linux_net'
    greenfield = create_owner 'greenfield_consulting'

    linux_bill = user_client(linux_net, 'bill')
    green_ralph = user_client(greenfield, 'ralph')

    system1 = linux_bill.register('system1')

    lambda do
      green_ralph.register('system2', :system, system1.uuid)
    end.should raise_exception(RestClient::BadRequest)
  end

  it "does not let an owner reregister another owner's consumer" do
    linux_net = create_owner 'linux_net'
    greenfield = create_owner 'greenfield_consulting'

    linux_bill = user_client(linux_net, 'bill')
    green_ralph = user_client(greenfield, 'ralph')

    system1 = linux_bill.register('system1')

    lambda do
      green_ralph.regenerate_identity_certificate(system1.uuid)
    end.should raise_exception(RestClient::Forbidden)
  end

  it 'should allow consumer to bind to products supporting multiple architectures' do
    owner = create_owner random_string('owner')
    owner_client = user_client(owner, random_string('testowner'))
    cp_client = consumer_client(owner_client, random_string('consumer123'), :system,
                                nil, 'uname.machine' => 'x86_64')
    prod = create_product(random_string('product'), random_string('product-multiple-arch'),
                          :attributes => { :arch => 'i386, x86_64'})
    subs = @cp.create_subscription(owner.key, prod.id)
    @cp.refresh_pools(owner.key)
    pool = cp_client.list_pools({:owner => owner['id']}).first

    cp_client.consume_pool(pool.id).size.should == 1
  end


  it 'should allow consumer to bind to products based on product quantity across pools' do
    owner = create_owner random_string('owner')
    owner_client = user_client(owner, random_string('testowner'))
    cp_client = consumer_client(owner_client, random_string('consumer123'), :system,
                                nil, 'cpu.cpu_socket(s)' => '4')
    prod1 = create_product(random_string('product'), random_string('product-stackable'),
                          :attributes => { :sockets => '2', :'multi-entitlement' => 'yes', :stacking_id => '8888'})
    prod2 = create_product(random_string('product'), random_string('product-stackable'),
                          :attributes => { :sockets => '2', :'multi-entitlement' => 'yes', :stacking_id => '8888'})
    @cp.create_subscription(owner.key, prod1.id, 2)
    @cp.create_subscription(owner.key, prod1.id, 8)
    @cp.create_subscription(owner.key, prod2.id, 5)


    @cp.refresh_pools(owner.key)

    total = 0
    cp_client.consume_product(prod1.id).each {|ent|  total += ent.quantity}
    total.should == 2

  end


  it 'should allow a consumer to specify their own UUID' do
    owner = create_owner random_string('owner')
    user = user_client(owner, random_string('billy'))

    consumer = user.register('machine1', :system, 'custom-uuid')
    consumer.uuid.should == 'custom-uuid'
  end

  it 'should allow a consumer to register with activation keys' do
    owner = create_owner random_string('owner')

    user1 = user_client(owner, random_string("user1"))
    consumer1 = consumer_client(user1, random_string("consumer1"))
    prod1 = create_product(random_string('product1'), random_string('product1'),
                           :attributes => { :'multi-entitlement' => 'yes'})
    subs1 = @cp.create_subscription(owner.key, prod1.id, 10)
    @cp.refresh_pools(owner.key)
    pool1 = consumer1.list_pools({:owner => owner['id']}).first

    # Connect without any credentials:
    client = Candlepin.new

    key1 = @cp.create_activation_key(owner['key'], 'key1')
    @cp.add_pool_to_key(key1['id'], pool1['id'], 3)
    @cp.create_activation_key(owner['key'], 'key2')
    consumer = client.register('machine1', :system, nil, {}, nil,
      owner['key'], ["key1", "key2"])
    consumer.uuid.should_not be_nil

    # TODO: Verify activation keys did what we expect once they are functional
    @cp.refresh_pools(owner.key)
    @cp.get_pool(pool1.id).consumed.should == 3
  end

  def verify_installed_pids(consumer, product_ids)
    installed_ids = consumer['installedProducts'].collect { |p| p['productId'] }
    installed_ids.length.should == product_ids.length
    product_ids.each do |pid|
      installed_ids.should include(pid)
    end
  end

  it 'should allow a consumer to register with and update installed products' do
    user = user_client(@owner1, random_string('billy'))
    pid1 = '918237'
    pid2 = '871234'
    pid3 = '712717'
    installed = [
        {'productId' => pid1, 'productName' => 'My Installed Product'},
        {'productId' => pid2, 'productName' => 'Another Installed Product'}]

    # Set a single fact, so we can make sure it doesn't get clobbered:
    facts = {
      'system.machine' => 'x86_64',
    }
    consumer = user.register('machine1', :system, nil, facts, nil, nil, [], installed)
    verify_installed_pids(consumer, [pid1, pid2])

    # Now update the installed packages:
    installed = [
        {'productId' => pid1, 'productName' => 'My Installed Product'},
        {'productId' => pid3, 'productName' => 'Third Installed Product'}]

    consumer_client = Candlepin.new(username=nil, password=nil,
        cert=consumer['idCert']['cert'],
        key=consumer['idCert']['key'])
    consumer_client.update_consumer({:installedProducts => installed})
    consumer = @cp.get_consumer(consumer['uuid'])
    verify_installed_pids(consumer, [pid1, pid3])

    # Make sure facts weren't clobbered:
    consumer['facts'].length.should == 1
  end

  it 'should allow a consumer to update their autoheal flag' do
    user_cp = user_client(@owner1, random_string('billy'))
    consumer = user_cp.register(random_string('system'), :system, nil,
      {}, nil, nil, [], [])
    consumer_client = Candlepin.new(username=nil, password=nil,
        cert=consumer['idCert']['cert'],
        key=consumer['idCert']['key'])

    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['autoheal'].should == true

    consumer_client.update_consumer({:autoheal => false})
    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['autoheal'].should == false

    # Empty update shouldn't modify the setting:
    consumer_client.update_consumer({})
    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['autoheal'].should == false
  end

  it 'should not allow the same UUID to be registered twice' do
    owner = create_owner random_string('owner')
    user = user_client(owner, random_string('willy'))

    # Register the UUID initially
    user.register('machine1', :system, 'ALF')

    # Second registration should be denied
    lambda do
      user.register('machine2', :system, 'ALF')
    end.should raise_exception(RestClient::BadRequest)
  end

  it 'should allow a consumer to unregister and free up the pool' do
    owner = create_owner('zowner')
    user = user_client(owner, 'cukebuster')
    # performs the register for us
    consumer = consumer_client(user, 'machine1')
    product = create_product()
    @cp.create_subscription(owner.key, product.id, 2)
    @cp.refresh_pools(owner.key)
    pool = consumer.list_pools(:consumer => consumer.uuid)[0]
    pool.consumed.should == 0
    consumer.consume_pool(pool.id)
    @cp.get_pool(pool.id).consumed.should == 1
    consumer.unregister(consumer.uuid)
    @cp.get_pool(pool.id).consumed.should == 0
  end

  it 'should allow adding guest ids to host consumer on update' do
    guests = [{'guestId' => 'guest1'}]

    user_cp = user_client(@owner1, random_string('test-user'))
    consumer = user_cp.register(random_string('host'), :system, nil,
      {}, nil, nil, [], [])
    consumer.should_not be_nil
    consumer['guestsIds'].should be_nil

    consumer_client = Candlepin.new(username=nil, password=nil,
        cert=consumer['idCert']['cert'],
        key=consumer['idCert']['key'])
    consumer_client.update_consumer({:guestsIds => guests})

    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 1
    consumer['guestsIds'][0]['guestId'].should == 'guest1'
  end

  it 'should allow updating guest ids from host consumer on update' do
    guests = [{'guestId' => 'guest1'},
              {'guestId' => 'guest2'}]

    user_cp = user_client(@owner1, random_string('test-user'))
    consumer = user_cp.register(random_string('host'), :system, nil,
      {}, nil, nil, [], [])

    consumer_client = Candlepin.new(username=nil, password=nil,
        cert=consumer['idCert']['cert'],
        key=consumer['idCert']['key'])
    consumer_client.update_consumer({:guestsIds => guests})

    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 2

    consumer_client.update_consumer({:guestsIds => [guests[1]]})
    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 1
    consumer['guestsIds'][0]['guestId'].should == 'guest2'
  end

  it 'should not modify guest id list if guestsIds list is null on update' do
    guests = [{'guestId' => 'guest1'}]

    user_cp = user_client(@owner1, random_string('test-user'))
    consumer = user_cp.register(random_string('host'), :system, nil,
      {}, nil, nil, [], [])

    consumer_client = Candlepin.new(username=nil, password=nil,
        cert=consumer['idCert']['cert'],
        key=consumer['idCert']['key'])
    consumer_client.update_consumer({:guestsIds => guests})

    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 1

    consumer_client.update_consumer({:guestsIds => nil})
    consumer_client.update_consumer({})
    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 1
    consumer['guestsIds'][0]['guestId'].should == 'guest1'
  end

  it 'should clear guest ids when empty list is provided on update' do
    guests = [{'guestId' => 'guest1'}]

    user_cp = user_client(@owner1, random_string('test-user'))
    consumer = user_cp.register(random_string('host'), :system, nil,
      {}, nil, nil, [], [])

    consumer_client = Candlepin.new(username=nil, password=nil,
        cert=consumer['idCert']['cert'],
        key=consumer['idCert']['key'])
    consumer_client.update_consumer({:guestsIds => guests})

    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 1

    consumer_client.update_consumer({:guestsIds => []})
    consumer = @cp.get_consumer(consumer['uuid'])
    consumer['guestsIds'].length.should == 0
  end

end
