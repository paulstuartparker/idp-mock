class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :email
      t.string :user_id
      t.string :business_id
      t.string :profile_id

      t.timestamps null: false
    end
  end
end
